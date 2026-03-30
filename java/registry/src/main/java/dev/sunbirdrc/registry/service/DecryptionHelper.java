package dev.sunbirdrc.registry.service;

import com.fasterxml.jackson.databind.JsonNode;
import dev.sunbirdrc.registry.exception.EncryptionException;
import dev.sunbirdrc.registry.util.PrivateField;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.Map;

@Component
public class DecryptionHelper extends PrivateField {

    public JsonNode getDecryptedJson(JsonNode rootNode) throws EncryptionException {
        Iterator<String> fieldNames = rootNode.fieldNames();
        if (!fieldNames.hasNext()) {
            throw new EncryptionException("Root node has no fields to decrypt");
        }
        String rootFieldName = fieldNames.next();
        process(rootNode.get(rootFieldName), rootFieldName, null);
        return rootNode;
    }

    protected Map<String, Object> performOperation(Map<String, Object> plainMap) throws EncryptionException {
        return encryptionService.decrypt(plainMap);
    }
}
