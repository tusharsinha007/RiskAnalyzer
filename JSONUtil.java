import java.util.HashMap;
import java.util.Map;

/**
 * A simple JSON utility class for parsing JSON responses.
 * This is a lightweight alternative to using a full JSON library.
 */
public class JSONUtil {
    
    /**
     * Extracts a string value from a JSON response.
     * 
     * @param json The JSON string
     * @param key The key to extract
     * @return The extracted string value, or null if not found
     */
    public static String getString(String json, String key) {
        if (json == null || key == null) {
            return null;
        }
        
        String searchKey = "\"" + key + "\":"; // "key":
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) {
            return null;
        }
        
        int valueStart = json.indexOf('"', keyIndex + searchKey.length());
        if (valueStart == -1) {
            return null;
        }
        
        int valueEnd = json.indexOf('"', valueStart + 1);
        if (valueEnd == -1) {
            return null;
        }
        
        return json.substring(valueStart + 1, valueEnd);
    }
    
    /**
     * Extracts an integer value from a JSON response.
     * 
     * @param json The JSON string
     * @param key The key to extract
     * @return The extracted integer value, or -1 if not found or not a valid integer
     */
    public static int getInt(String json, String key) {
        if (json == null || key == null) {
            return -1;
        }
        
        String searchKey = "\"" + key + "\":"; // "key":
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) {
            return -1;
        }
        
        int valueStart = keyIndex + searchKey.length();
        int valueEnd = json.indexOf(',', valueStart);
        if (valueEnd == -1) {
            valueEnd = json.indexOf('}', valueStart);
            if (valueEnd == -1) {
                return -1;
            }
        }
        
        String valueStr = json.substring(valueStart, valueEnd).trim();
        try {
            return Integer.parseInt(valueStr);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    /**
     * Extracts a JSON object as a string from a JSON response.
     * 
     * @param json The JSON string
     * @param key The key to extract
     * @return The extracted JSON object as a string, or null if not found
     */
    public static String getJSONObject(String json, String key) {
        if (json == null || key == null) {
            return null;
        }
        
        String searchKey = "\"" + key + "\":"; // "key":
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) {
            return null;
        }
        
        int objectStart = json.indexOf('{', keyIndex + searchKey.length());
        if (objectStart == -1) {
            return null;
        }
        
        // Count opening and closing braces to find the matching closing brace
        int braceCount = 1;
        int objectEnd = objectStart + 1;
        while (braceCount > 0 && objectEnd < json.length()) {
            char c = json.charAt(objectEnd);
            if (c == '{') {
                braceCount++;
            } else if (c == '}') {
                braceCount--;
            }
            objectEnd++;
        }
        
        if (braceCount != 0) {
            return null; // Unbalanced braces
        }
        
        return json.substring(objectStart, objectEnd);
    }
    
    /**
     * Extracts a JSON array as a string from a JSON response.
     * 
     * @param json The JSON string
     * @param key The key to extract
     * @return The extracted JSON array as a string, or null if not found
     */
    public static String getJSONArray(String json, String key) {
        if (json == null || key == null) {
            return null;
        }
        
        String searchKey = "\"" + key + "\":"; // "key":
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) {
            return null;
        }
        
        int arrayStart = json.indexOf('[', keyIndex + searchKey.length());
        if (arrayStart == -1) {
            return null;
        }
        
        // Count opening and closing brackets to find the matching closing bracket
        int bracketCount = 1;
        int arrayEnd = arrayStart + 1;
        while (bracketCount > 0 && arrayEnd < json.length()) {
            char c = json.charAt(arrayEnd);
            if (c == '[') {
                bracketCount++;
            } else if (c == ']') {
                bracketCount--;
            }
            arrayEnd++;
        }
        
        if (bracketCount != 0) {
            return null; // Unbalanced brackets
        }
        
        return json.substring(arrayStart, arrayEnd);
    }
    
    /**
     * Checks if a JSON response contains an error.
     * 
     * @param json The JSON string
     * @return true if the JSON contains an error, false otherwise
     */
    public static boolean hasError(String json) {
        return json != null && json.contains("\"error\":");
    }
    
    /**
     * Extracts the error message from a JSON response.
     * 
     * @param json The JSON string
     * @return The error message, or null if not found
     */
    public static String getErrorMessage(String json) {
        if (!hasError(json)) {
            return null;
        }
        
        return getString(json, "message");
    }
    
    /**
     * Extracts a map of security vendors and their detections from a JSON response.
     * 
     * @param json The JSON string containing security vendor data
     * @return A map of vendor names to their detection results
     */
    public static Map<String, String> extractSecurityVendors(String json) {
        Map<String, String> vendors = new HashMap<>();
        if (json == null) {
            return vendors;
        }
        
        String vendorsData = getJSONObject(json, "security_vendors_data");
        if (vendorsData == null) {
            return vendors;
        }
        
        // This is a simplified approach - in a real implementation, you would use a more robust JSON parser
        // Extract vendor names and their detection results
        int currentPos = 0;
        while (true) {
            int vendorStart = vendorsData.indexOf('"', currentPos);
            if (vendorStart == -1) break;
            
            int vendorEnd = vendorsData.indexOf('"', vendorStart + 1);
            if (vendorEnd == -1) break;
            
            String vendorName = vendorsData.substring(vendorStart + 1, vendorEnd);
            
            // Find the detection result for this vendor
            String searchKey = "\"category\":"; // "category":
            int categoryStart = vendorsData.indexOf(searchKey, vendorEnd);
            if (categoryStart == -1) break;
            
            int valueStart = vendorsData.indexOf('"', categoryStart + searchKey.length());
            if (valueStart == -1) break;
            
            int valueEnd = vendorsData.indexOf('"', valueStart + 1);
            if (valueEnd == -1) break;
            
            String detection = vendorsData.substring(valueStart + 1, valueEnd);
            vendors.put(vendorName, detection);
            
            currentPos = valueEnd + 1;
        }
        
        return vendors;
    }
}