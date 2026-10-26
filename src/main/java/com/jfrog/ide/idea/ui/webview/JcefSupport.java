package com.jfrog.ide.idea.ui.webview;

import com.intellij.ui.jcef.JBCefApp;
import com.jfrog.ide.idea.log.Logger;

/**
 * Whether the IDE can show the embedded browser.
 */
public final class JcefSupport {

    private JcefSupport() {
    }

    /**
     * @return true when the embedded browser is on the classpath and reports itself supported.
     * A missing browser class is treated as unavailable, the same way a missing optional plugin is.
     */
    public static boolean isAvailable() {
        try {
            return JBCefApp.isSupported();
        } catch (NoClassDefFoundError e) {
            Logger.getInstance().warn("JCEF is not available. The issue details view needs the Web Browser plugin.");
            return false;
        }
    }
}
