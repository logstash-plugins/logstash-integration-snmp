package org.logstash.snmp.mib;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.smi.OID;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static java.util.Objects.nonNull;

class OidTrie {
    private static final Logger logger = LogManager.getLogger(OidTrie.class);
    private final OidTrieNode root;

    OidTrie() {
        this.root = new OidTrieNode(0);
    }

    void insert(OID oid, OidData data) {
        final int[] oidIdentifiers = oid.getValue();

        Map<Integer, OidTrieNode> current = root.getChildren();
        for (int i = 0; i < oidIdentifiers.length; i++) {
            final int oidIdentifier = oidIdentifiers[i];

            final OidTrieNode node;
            if (current.containsKey(oidIdentifier)) {
                node = current.get(oidIdentifier);
            } else {
                node = new OidTrieNode(oidIdentifier);
                current.put(oidIdentifier, node);
            }

            current = node.getChildren();
            if (i + 1 == oidIdentifiers.length) {
                if (!node.hasData()) {
                    node.setData(data);
                } else if (!node.getData().equalsIgnoreModuleName(data)) {
                    logger.warn("warning: overwriting MIB OID '{}' and name '{}' with new name '{}' from module '{}'",
                            oid, node.getData().getName(), data.getName(), data.getModuleName());
                    node.setData(data);
                }
            }
        }
    }

    Optional<OidData> find(OID oid) {
        return find(oid, null);
    }

    Optional<OidData> find(OID oid, Consumer<OidTrieNode> edgesConsumer) {
        OidTrieNode current = root;

        final int[] oidIdentifiers = oid.getValue();
        for (int identifier : oidIdentifiers) {
            OidTrieNode node = current.getChildren().get(identifier);
            if (node == null) {
                return Optional.empty();
            }

            if (edgesConsumer != null) {
                edgesConsumer.accept(node);
            }

            current = node;
        }

        if (current.hasData()) {
            return Optional.ofNullable(current.getData());
        }

        return Optional.empty();
    }

    static class OidTrieNode {
        private final int identifier;
        private final HashMap<Integer, OidTrieNode> children = new HashMap<>();
        private OidData data;

        public OidTrieNode(int identifier) {
            this.identifier = identifier;
        }

        int getIdentifier() {
            return identifier;
        }

        Map<Integer, OidTrieNode> getChildren() {
            return children;
        }

        OidData getData() {
            return data;
        }

        void setData(OidData data) {
            this.data = data;
        }

        boolean hasData() {
            return nonNull(data);
        }
    }
}
