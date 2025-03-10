import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Utility class for loading custom icons for the application.
 * This replaces the AppIconCreator class as the user will provide their own icon.
 */
public class IconLoader {
    
    /**
     * Loads an icon from the specified file path.
     * 
     * @param iconPath The path to the icon file
     * @return The loaded ImageIcon, or null if loading fails
     */
    public static ImageIcon loadIcon(String iconPath) {
        try {
            File iconFile = new File(iconPath);
            if (iconFile.exists()) {
                return new ImageIcon(iconFile.getAbsolutePath());
            } else {
                System.err.println("Icon file not found: " + iconPath);
                return null;
            }
        } catch (Exception e) {
            System.err.println("Error loading icon: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Loads an icon and returns it as an Image object.
     * 
     * @param iconPath The path to the icon file
     * @return The loaded Image, or null if loading fails
     */
    public static Image loadIconAsImage(String iconPath) {
        ImageIcon icon = loadIcon(iconPath);
        return (icon != null) ? icon.getImage() : null;
    }
}