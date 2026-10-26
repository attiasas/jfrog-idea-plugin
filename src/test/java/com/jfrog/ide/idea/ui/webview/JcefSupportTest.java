package com.jfrog.ide.idea.ui.webview;

import com.intellij.testFramework.fixtures.LightJavaCodeInsightFixtureTestCase;
import com.intellij.ui.jcef.JBCefApp;
import com.jfrog.ide.idea.ui.JFrogLocalToolWindow;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.swing.*;
import java.awt.*;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class JcefSupportTest extends LightJavaCodeInsightFixtureTestCase {

    public void testMissingBrowserClassIsUnavailable() {
        try (MockedStatic<JBCefApp> jcef = Mockito.mockStatic(JBCefApp.class)) {
            jcef.when(JBCefApp::isSupported).thenThrow(new NoClassDefFoundError("com/intellij/ui/jcef/JBCefApp"));
            assertFalse(JcefSupport.isAvailable());
        }
    }

    public void testSupportedBrowserIsAvailable() {
        try (MockedStatic<JBCefApp> jcef = Mockito.mockStatic(JBCefApp.class)) {
            jcef.when(JBCefApp::isSupported).thenReturn(true);
            assertTrue(JcefSupport.isAvailable());
        }
    }

    public void testUnsupportedBrowserIsUnavailable() {
        try (MockedStatic<JBCefApp> jcef = Mockito.mockStatic(JBCefApp.class)) {
            jcef.when(JBCefApp::isSupported).thenReturn(false);
            assertFalse(JcefSupport.isAvailable());
        }
    }

    public void testUnsupportedBrowserShowsMissingComponentMessage() {
        try (MockedStatic<JBCefApp> jcef = Mockito.mockStatic(JBCefApp.class)) {
            jcef.when(JBCefApp::isSupported).thenReturn(false);
            JFrogLocalToolWindow window = new JFrogLocalToolWindow(getProject());
            try {
                assertTrue(componentText(window.getContent()).contains("JCEF that seem to be missing"));
            } finally {
                window.dispose();
            }
        }
    }

    private static String componentText(Component component) {
        StringBuilder text = new StringBuilder();
        appendText(component, text);
        return text.toString();
    }

    private static void appendText(Component component, StringBuilder text) {
        if (component instanceof JLabel label && label.getText() != null) {
            text.append(label.getText());
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                appendText(child, text);
            }
        }
    }

    public void testBrowserDependencyIsOptional() throws Exception {
        try (InputStream in = JcefSupportTest.class.getClassLoader().getResourceAsStream("META-INF/plugin.xml")) {
            assertNotNull(in);
            String xml = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(xml.contains("<depends config-file=\"with-jcef.xml\" optional=\"true\">com.intellij.modules.jcef</depends>"));
        }
    }
}
