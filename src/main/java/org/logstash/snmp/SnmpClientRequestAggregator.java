package org.logstash.snmp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.Target;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class SnmpClientRequestAggregator implements AutoCloseable {
    private static final Logger logger = LogManager.getLogger(SnmpClientRequestAggregator.class);
    private final ExecutorService executor;

    public SnmpClientRequestAggregator(int threadPoolSize, String threadPoolName) {
        this.executor = Executors.newFixedThreadPool(threadPoolSize, new NamedThreadFactory(threadPoolName));
    }

    public Request createRequest(SnmpClient client) {
        return new Request(client, executor);
    }

    public void await(Request[] requests, int timeoutMillis) throws ExecutionException, TimeoutException {
        @SuppressWarnings("rawtypes") final CompletableFuture[] futures = Arrays.stream(requests)
                .map(Request::toCompletableFuture)
                .toArray(CompletableFuture[]::new);

        try {
            CompletableFuture.allOf(futures).get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            logger.error("an unexpected error happened while executing SNMP requests", e.getCause());
            throw e;
        } catch (InterruptedException e) {
            logger.error("worker thread was interrupted while executing SNMP requests. Aborting", e);
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        boolean terminated = executor.isTerminated();
        if (terminated) {
            return;
        }

        executor.shutdown();
        try {
            terminated = executor.awaitTermination(1, TimeUnit.MINUTES);
            if (!terminated) {
                executor.shutdownNow();
                terminated = executor.awaitTermination(30, TimeUnit.SECONDS);
            }

            if (!terminated) {
                logger.info("failed to stop multi-thread request aggregator pool. Ignoring");
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public static class Request {
        private final Executor executor;
        private final SnmpClient client;
        private final ConcurrentLinkedQueue<CompletableFuture<Map<String, ?>>> futures = new ConcurrentLinkedQueue<>();
        private final Map<String, Object> result = new ConcurrentHashMap<>();

        public Request(SnmpClient client, Executor executor) {
            this.client = client;
            this.executor = executor;
        }

        public void get(Target<Address> target, OID[] oids) {
            submitRequestTask(target, "get", oids, Map.of(), () -> {
                try {
                    return client.get(target, oids);
                } catch (IOException e) {
                    throw new CompletionException(e);
                }
            });
        }

        public void walk(Target<Address> target, OID oid) {
            submitRequestTask(target, "walk", new OID[]{oid}, Map.of(), () -> client.walk(target, oid));
        }

        public void table(Target<Address> target, String tableName, OID[] oids) {
            submitRequestTask(target, "table", oids, Map.of("table_name", tableName), () -> client.table(target, tableName, oids));
        }

        private void submitRequestTask(Target<Address> target, String operation, OID[] oids, Map<String, String> extraLogDetails, Supplier<Map<String, ?>> task) {
            final Supplier<Map<String, String>> logPropertiesSupplier = () -> createLogDetails(target, oids, extraLogDetails);

            final CompletableFuture<Map<String, ?>> future = CompletableFuture.supplyAsync(task, executor)
                    .exceptionally(ex -> handleRequestException(operation, ex, logPropertiesSupplier));

            future.thenAccept(data -> handleRequestData(operation, data, logPropertiesSupplier));

            this.futures.add(future);
        }

        private void handleRequestData(String operation, Map<String, ?> data, Supplier<Map<String, String>> logPropertiesSupplier) {
            if (data != null && !data.isEmpty()) {
                result.putAll(data);
            } else if (data != null && logger.isDebugEnabled()) {
                logger.debug("`{}` operation returned no response. {}", operation, logPropertiesSupplier.get());
            }
        }

        private Map<String, ?> handleRequestException(String operation, Throwable ex, Supplier<Map<String, String>> logPropertiesSupplier) {
            final Throwable throwable = getWrappedException(ex);
            final Map<String, String> logProperties = logPropertiesSupplier.get();

            if (logger.isDebugEnabled()){
                logger.error("error invoking `{}` operation, ignoring. {}", operation, logProperties, throwable);
            } else {
                final String errorMessage = throwable != null ? throwable.getMessage() : null;
                logger.error("error invoking `{}` operation: {}, ignoring. {}", operation, errorMessage, logProperties);
            }

            // Should return null (instead of empty), so it can be differentiated on the #handleRequestData from an empty response
            return null;
        }

        private Throwable getWrappedException(Throwable throwable) {
            if (throwable instanceof CompletionException && throwable.getCause() != null) {
                return throwable.getCause();
            }

            return throwable;
        }

        static Map<String, String> createLogDetails(Target<Address> target, OID[] oids, Map<String, String> extraDetails) {
            final Map<String, String> map = new HashMap<>(extraDetails);
            map.putIfAbsent("host", String.valueOf(target.getAddress()));
            map.putIfAbsent("oids", Arrays.toString(oids));
            return map;
        }

        public CompletableFuture<Void> getResultAsync(Consumer<Map<String, Object>> consumer) {
            return toCompletableFuture()
                    .thenAccept(p -> consumer.accept(new HashMap<>(this.result)));
        }

        CompletableFuture<Void> toCompletableFuture() {
            return CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new));
        }
    }

    private static class NamedThreadFactory implements ThreadFactory {
        private final String name;
        private final AtomicInteger threadNumber = new AtomicInteger(0);
        private final ThreadFactory defaultThreadFactory = Executors.defaultThreadFactory();

        public NamedThreadFactory(String name) {
            this.name = name;
        }

        @Override
        public Thread newThread(Runnable runnable) {
            final Thread newThread = defaultThreadFactory.newThread(runnable);
            newThread.setName(String.format("%s-%d", name, threadNumber.addAndGet(1)));
            return newThread;
        }
    }
}
