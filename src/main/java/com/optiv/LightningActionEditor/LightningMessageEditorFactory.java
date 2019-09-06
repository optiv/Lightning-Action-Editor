/*
This file is part of LightningActionEditor.

LightningActionEditor is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

LightningActionEditor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with LightningActionEditor.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.optiv.LightningActionEditor;

import burp.*;

import javax.swing.*;
import java.awt.*;

public class LightningMessageEditorFactory implements IMessageEditorTabFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public LightningMessageEditorFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new LightningMessageEditorTab(controller, editable);
    }

    class LightningMessageEditorTab implements IMessageEditorTab {
        private final boolean editable;
        private final JTabbedPane editorTabPanel;
        private byte[] currentMessage;

        private final ITextEditor messageHeader;
        private final ITextEditor contextHeader;
        private final ITextEditor pageUriHeader;
        private final ITextEditor tokenHeader;

        LightningMessageEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            editorTabPanel = new JTabbedPane();

            messageHeader = callbacks.createTextEditor();
            contextHeader = callbacks.createTextEditor();
            pageUriHeader = callbacks.createTextEditor();
            tokenHeader = callbacks.createTextEditor();

            editorTabPanel.addTab("Message", messageHeader.getComponent());
            editorTabPanel.addTab("Context", contextHeader.getComponent());
            editorTabPanel.addTab("Page URI", pageUriHeader.getComponent());
            editorTabPanel.addTab("Token", tokenHeader.getComponent());
        }

        @Override
        public String getTabCaption() {
            return "Lightning";
        }

        @Override
        public Component getUiComponent() {
            return editorTabPanel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return isRequest && Utils.isLightningRequest(content, helpers);
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (!isRequest || content == null) {
                messageHeader.setText(null);
                messageHeader.setEditable(false);

                contextHeader.setText(null);
                contextHeader.setEditable(false);

                pageUriHeader.setText(null);
                pageUriHeader.setEditable(false);

                tokenHeader.setText(null);
                tokenHeader.setEditable(false);
            } else {
                messageHeader.setEditable(editable);
                contextHeader.setEditable(editable);
                pageUriHeader.setEditable(editable);
                tokenHeader.setEditable(editable);

                messageHeader.setText(helpers.stringToBytes(Utils.prettyPrintJson(helpers.urlDecode(helpers.getRequestParameter(content, "message").getValue()))));
                contextHeader.setText(helpers.stringToBytes(Utils.prettyPrintJson(helpers.urlDecode(helpers.getRequestParameter(content, "aura.context").getValue()))));
                pageUriHeader.setText(helpers.stringToBytes(helpers.urlDecode(helpers.getRequestParameter(content, "aura.pageURI").getValue())));
                tokenHeader.setText(helpers.stringToBytes(helpers.urlDecode(helpers.getRequestParameter(content, "aura.token").getValue())));
            }

            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            if (isModified()) {
                byte[] modifiedMessage = currentMessage.clone();
                if (messageHeader.isTextModified()) {
                    byte[] text = messageHeader.getText();
                    String input = helpers.urlEncode(Utils.unPrettyPrintJson(helpers.bytesToString(text)));

                    modifiedMessage = helpers.updateParameter(modifiedMessage, helpers.buildParameter("message", input, IParameter.PARAM_BODY));
                }

                if (contextHeader.isTextModified()) {
                    byte[] text = contextHeader.getText();
                    String input = helpers.urlEncode(Utils.unPrettyPrintJson(helpers.bytesToString(text)));

                    modifiedMessage = helpers.updateParameter(modifiedMessage, helpers.buildParameter("aura.context", input, IParameter.PARAM_BODY));
                }

                if (pageUriHeader.isTextModified()) {
                    byte[] text = pageUriHeader.getText();
                    String input = helpers.urlEncode(helpers.bytesToString(text));

                    modifiedMessage = helpers.updateParameter(modifiedMessage, helpers.buildParameter("aura.pageURI", input, IParameter.PARAM_BODY));
                }

                if (tokenHeader.isTextModified()) {
                    byte[] text = tokenHeader.getText();
                    String input = helpers.urlEncode(helpers.bytesToString(text));

                    modifiedMessage = helpers.updateParameter(modifiedMessage, helpers.buildParameter("aura.token", input, IParameter.PARAM_BODY));
                }

                return modifiedMessage;
            }

            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return messageHeader.isTextModified() || contextHeader.isTextModified() || pageUriHeader.isTextModified() || tokenHeader.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return null;
        }
    }
}
