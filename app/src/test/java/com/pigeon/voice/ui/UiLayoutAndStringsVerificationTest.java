package com.pigeon.voice.ui;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class UiLayoutAndStringsVerificationTest {

    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    private static final String APP_NS = "http://schemas.android.com/apk/res-auto";

    private File resolveResFile(String relativePath) {
        File direct = new File("src/main/res/" + relativePath);
        if (direct.exists()) {
            return direct;
        }
        return new File("app/src/main/res/" + relativePath);
    }

    private Document parseXml(File file) throws Exception {
        assertTrue("Expected resource file to exist: " + file.getAbsolutePath(), file.exists());
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(file);
    }

    private Element findByAndroidId(Document doc, String idSuffix) {
        NodeList all = doc.getElementsByTagName("*");
        String target = "@+id/" + idSuffix;
        for (int i = 0; i < all.getLength(); i++) {
            Node node = all.item(i);
            if (node instanceof Element) {
                Element el = (Element) node;
                String id = el.getAttributeNS(ANDROID_NS, "id");
                if (target.equals(id)) {
                    return el;
                }
            }
        }
        return null;
    }

    @Test
    public void testMainScreenButtonStringsAreShortenedForSingleLineDisplay() throws Exception {
        Document doc = parseXml(resolveResFile("values/strings.xml"));
        NodeList strings = doc.getElementsByTagName("string");
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < strings.getLength(); i++) {
            Element el = (Element) strings.item(i);
            map.put(el.getAttribute("name"), el.getTextContent().trim());
        }

        String chooseContact = map.get("choose_contact");
        String addContact = map.get("add_contact");
        String joinCallBtn = map.get("join_call_btn");
        String startHostingBtn = map.get("start_hosting_btn");

        assertNotNull(chooseContact);
        assertNotNull(addContact);
        assertNotNull(joinCallBtn);
        assertNotNull(startHostingBtn);

        assertTrue("choose_contact text must be shortened (<= 16 chars), got: " + chooseContact,
                chooseContact.length() <= 16);
        assertTrue("add_contact text must be concise (<= 16 chars), got: " + addContact,
                addContact.length() <= 16);
        assertTrue("join_call_btn text must be shortened (<= 22 chars), got: " + joinCallBtn,
                joinCallBtn.length() <= 22);
        assertTrue("start_hosting_btn text must be concise (<= 28 chars), got: " + startHostingBtn,
                startHostingBtn.length() <= 28);

        assertNotNull("mute_mic accessibility string must exist", map.get("mute_mic"));
        assertNotNull("unmute_mic accessibility string must exist", map.get("unmute_mic"));
    }

    @Test
    public void testMainScreenButtonPairsAreAlignedAndSingleLine() throws Exception {
        Document doc = parseXml(resolveResFile("layout/activity_main.xml"));

        Element btnChooseContact = findByAndroidId(doc, "btnChooseContact");
        Element btnAddContact = findByAndroidId(doc, "btnAddContact");
        assertNotNull(btnChooseContact);
        assertNotNull(btnAddContact);

        assertPairAlignedAndSingleLine(btnChooseContact, btnAddContact);
        assertCompactPaddingAndLetterSpacing(btnChooseContact, 12);
        assertCompactPaddingAndLetterSpacing(btnAddContact, 12);

        Element btnPasteToken = findByAndroidId(doc, "btnPasteToken");
        Element btnJoinCall = findByAndroidId(doc, "btnJoinCall");
        assertNotNull(btnPasteToken);
        assertNotNull(btnJoinCall);

        assertPairAlignedAndSingleLine(btnPasteToken, btnJoinCall);
        assertCompactPaddingAndLetterSpacing(btnPasteToken, 12);
        assertCompactPaddingAndLetterSpacing(btnJoinCall, 12);

        Element btnHostCall = findByAndroidId(doc, "btnHostCall");
        assertNotNull(btnHostCall);
        assertCompactPaddingAndLetterSpacing(btnHostCall, 12);
    }

    @Test
    public void testCallScreenMuteButtonUsesIconInsteadOfTextAndAlignsRow() throws Exception {
        Document doc = parseXml(resolveResFile("layout/activity_call.xml"));

        Element btnToggleMute = findByAndroidId(doc, "btnToggleMute");
        Element btnToggleSpeaker = findByAndroidId(doc, "btnToggleSpeaker");
        Element btnEndCall = findByAndroidId(doc, "btnEndCall");

        assertNotNull(btnToggleMute);
        assertNotNull(btnToggleSpeaker);
        assertNotNull(btnEndCall);

        // Mute button must use centered icon instead of text
        assertEquals("Mute button text must be empty (icon-only)",
                "", btnToggleMute.getAttributeNS(ANDROID_NS, "text"));
        assertEquals("@drawable/ic_mic_on", btnToggleMute.getAttributeNS(APP_NS, "icon"));
        assertEquals("textStart", btnToggleMute.getAttributeNS(APP_NS, "iconGravity"));
        assertEquals("0dp", btnToggleMute.getAttributeNS(APP_NS, "iconPadding"));
        assertEquals("center", btnToggleMute.getAttributeNS(ANDROID_NS, "gravity"));
        assertEquals("center", btnToggleMute.getAttributeNS(ANDROID_NS, "textAlignment"));
        assertEquals("0dp", btnToggleMute.getAttributeNS(ANDROID_NS, "paddingStart"));
        assertEquals("0dp", btnToggleMute.getAttributeNS(ANDROID_NS, "paddingEnd"));
        assertEquals("@string/mute_mic", btnToggleMute.getAttributeNS(ANDROID_NS, "contentDescription"));

        // Verify all 3 call control buttons share the same aligned row, height, and compact padding
        assertPairAlignedAndSingleLine(btnToggleMute, btnToggleSpeaker);
        assertCompactPaddingAndLetterSpacing(btnToggleSpeaker, 8);
        assertCompactPaddingAndLetterSpacing(btnEndCall, 8);
        assertEquals(
                btnToggleMute.getAttributeNS(ANDROID_NS, "layout_height"),
                btnEndCall.getAttributeNS(ANDROID_NS, "layout_height"));
        assertEquals("0dp", btnEndCall.getAttributeNS(ANDROID_NS, "insetTop"));
        assertEquals("0dp", btnEndCall.getAttributeNS(ANDROID_NS, "insetBottom"));
    }

    private void assertCompactPaddingAndLetterSpacing(Element button, int maxHorizontalPaddingDp) {
        String padStart = button.getAttributeNS(ANDROID_NS, "paddingStart");
        String padEnd = button.getAttributeNS(ANDROID_NS, "paddingEnd");
        String letterSpacing = button.getAttributeNS(ANDROID_NS, "letterSpacing");

        assertTrue("Button must set explicit paddingStart in dp", padStart.endsWith("dp"));
        assertTrue("Button must set explicit paddingEnd in dp", padEnd.endsWith("dp"));
        int startDp = Integer.parseInt(padStart.replace("dp", ""));
        int endDp = Integer.parseInt(padEnd.replace("dp", ""));
        assertTrue("paddingStart must be <= " + maxHorizontalPaddingDp + "dp to prevent truncation",
                startDp <= maxHorizontalPaddingDp);
        assertTrue("paddingEnd must be <= " + maxHorizontalPaddingDp + "dp to prevent truncation",
                endDp <= maxHorizontalPaddingDp);
        assertEquals("0.01", letterSpacing);
    }

    private void assertPairAlignedAndSingleLine(Element leftBtn, Element rightBtn) {
        assertEquals("Buttons in horizontal row must share the exact same parent container",
                leftBtn.getParentNode(), rightBtn.getParentNode());
        Element parentRow = (Element) leftBtn.getParentNode();

        assertEquals("Parent LinearLayout must disable baselineAligned to prevent vertical offset",
                "false", parentRow.getAttributeNS(ANDROID_NS, "baselineAligned"));
        assertEquals("Parent LinearLayout must center children vertically",
                "center_vertical", parentRow.getAttributeNS(ANDROID_NS, "gravity"));

        String leftHeight = leftBtn.getAttributeNS(ANDROID_NS, "layout_height");
        String rightHeight = rightBtn.getAttributeNS(ANDROID_NS, "layout_height");
        assertEquals("Paired buttons must have identical layout_height", leftHeight, rightHeight);
        assertTrue("Button height must be explicit dp", leftHeight.endsWith("dp"));

        assertEquals("0dp", leftBtn.getAttributeNS(ANDROID_NS, "insetTop"));
        assertEquals("0dp", leftBtn.getAttributeNS(ANDROID_NS, "insetBottom"));
        assertEquals("0dp", rightBtn.getAttributeNS(ANDROID_NS, "insetTop"));
        assertEquals("0dp", rightBtn.getAttributeNS(ANDROID_NS, "insetBottom"));

        if (!leftBtn.getAttributeNS(ANDROID_NS, "text").isEmpty()) {
            assertEquals("1", leftBtn.getAttributeNS(ANDROID_NS, "maxLines"));
            assertEquals("true", leftBtn.getAttributeNS(ANDROID_NS, "singleLine"));
        }
        if (!rightBtn.getAttributeNS(ANDROID_NS, "text").isEmpty()) {
            assertEquals("1", rightBtn.getAttributeNS(ANDROID_NS, "maxLines"));
            assertEquals("true", rightBtn.getAttributeNS(ANDROID_NS, "singleLine"));
        }
    }
}
