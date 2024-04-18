package org.logstash.snmp.mib;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.io.JsonStringEncoder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.smi.OID;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

class SmilibPythonMibReader implements MibReader {

    private static final Logger logger = LogManager.getLogger(SmilibPythonMibReader.class);
    static final String FILE_EXTENSION = "dic";
    private static final String TRIPLE_QUOTED_STRING_PATTERN = "((\\\"\\\"\\\")([\\w\\W]*?)(\\\"\\\"\\\"))";
    private static final Map<String, String> CONTENT_REPLACE_TOKENS = Map.of(
            ": (", ": [",
            "),\n", "],\n"
    );
    private static final Pattern CONTENT_REPLACE_PATTERN = Pattern.compile(
            String.format("(%s|%s)", createContentReplaceTokensPattern(), TRIPLE_QUOTED_STRING_PATTERN));

    private static String createContentReplaceTokensPattern() {
        return CONTENT_REPLACE_TOKENS
                .keySet()
                .stream()
                .map(Pattern::quote)
                .collect(Collectors.joining("|"));
    }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            .enable(JsonParser.Feature.ALLOW_COMMENTS)
            .enable(JsonParser.Feature.ALLOW_YAML_COMMENTS)
            .enable(JsonParser.Feature.ALLOW_UNQUOTED_CONTROL_CHARS)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @Override
    public void read(Collection<Path> paths, BiConsumer<OID, OidData> consumer) throws InvalidMibFileException {
        for (final Path path : paths) {
            String content;
            try {
                content = sanitize(Files.readString(path));
            } catch (Exception e) {
                throw new InvalidMibFileException(String.format("Error reading MIB file: %s", path), e);
            }

            final JsonNode jsonNode;
            try {
                jsonNode = MAPPER.readTree(content);
            } catch (Exception e) {
                throw new InvalidMibFileException(String.format("Error parsing MIB file: %s", path), e);
            }

            final JsonNode nodes = jsonNode.get("nodes");
            if (nodes == null) {
                logger.warn("The MIB file `{}` does not contain any node definition. Skipping", path);
                continue;
            }

            for (Iterator<Map.Entry<String, JsonNode>> it = nodes.fields(); it.hasNext(); ) {
                final Map.Entry<String, JsonNode> property = it.next();
                readNode(path, property.getKey(), property.getValue(), consumer);
            }

            final JsonNode notifications = jsonNode.get("notifications");
            if (notifications != null) {
                for (Iterator<Map.Entry<String, JsonNode>> it = notifications.fields(); it.hasNext(); ) {
                    final Map.Entry<String, JsonNode> property = it.next();
                    readNode(path, property.getKey(), property.getValue(), consumer);
                }
            }
        }
    }

    private void readNode(Path path, String nodeName, JsonNode node, BiConsumer<OID, OidData> consumer) {
        final JsonNode oidNode = node.get("oid");
        if (oidNode == null) {
            logger.warn("The MIB file `{}` node `{}` has no defined OID. Skipping", path, nodeName);
            return;
        }

        final OID oid;
        try {
            oid = new OID(oidNode.textValue());
        } catch (RuntimeException e) {
            logger.warn("The MIB file `{}` node `{}` has an invalid OID value `{}`. Skipping", path, nodeName, oidNode.textValue());
            return;
        }

        final String nodeType = Optional.ofNullable(node.get("nodetype"))
                .map(JsonNode::textValue)
                .orElse("node");

        final String moduleName = Optional.ofNullable(node.get("moduleName"))
                .map(JsonNode::textValue)
                .orElseGet(() -> FileUtils.getFileNameWithoutExtension(path));

        consumer.accept(oid, new OidData(nodeType, nodeName, moduleName));
    }

    private String sanitize(String content) {
        final String mibDictionary = content.substring(content.indexOf("MIB = ") + 6);
        final Matcher matcher = CONTENT_REPLACE_PATTERN.matcher(mibDictionary);
        final StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            // Replace content tokens
            if (CONTENT_REPLACE_TOKENS.containsKey(matcher.group(1))) {
                matcher.appendReplacement(sb, CONTENT_REPLACE_TOKENS.get(matcher.group(1)));
            }

            // Check if the match group is the python multi-line value (TRIPLE_QUOTED_STRING_PATTERN) and encode
            // the content (without quotes) to be compatible with JSON.
            if (matcher.groupCount() > 3 && "\"\"\"".equals(matcher.group(3))) {
                try {
                    final char[] chars = JsonStringEncoder
                            .getInstance()
                            .quoteAsString(matcher.group(4));

                    matcher.appendReplacement(sb, Matcher.quoteReplacement("\"" + new String(chars) + "\""));
                } catch (Exception e) {
                    throw new InvalidMibFileException(e);
                }
            }
        }

        matcher.appendTail(sb);
        return sb.toString();
    }
}
