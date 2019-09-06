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
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.List;

public class LightningActionsTab extends AbstractTableModel implements ITab, IMessageEditorController, IHttpListener {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    private ActionEntry currentActionEntry;
    private SendMenu contextMenu;

    private final List<ActionEntry> actions = new ArrayList<>();

    public LightningActionsTab(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // create our UI
        SwingUtilities.invokeLater(() -> {
            // main split pane
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            // table of action entries
            Table actionTable = new Table(LightningActionsTab.this);
            JScrollPane scrollPane = new JScrollPane(actionTable);
            splitPane.setLeftComponent(scrollPane);

            // tabs with request/response viewers
            JTabbedPane tabs = new JTabbedPane();
            requestViewer = callbacks.createMessageEditor(LightningActionsTab.this, false);
            responseViewer = callbacks.createMessageEditor(LightningActionsTab.this, false);
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());
            splitPane.setRightComponent(tabs);

            // customize our UI components
            callbacks.customizeUiComponent(splitPane);
            callbacks.customizeUiComponent(actionTable);
            callbacks.customizeUiComponent(scrollPane);
            callbacks.customizeUiComponent(tabs);

            contextMenu = new SendMenu();

            actionTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                        contextMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    int selectedRow = actionTable.rowAtPoint(e.getPoint());
                    if (selectedRow >= 0 && selectedRow < actionTable.getRowCount()) {
                        if (!actionTable.getSelectionModel().isSelectedIndex(selectedRow)) {
                            actionTable.setRowSelectionInterval(selectedRow, selectedRow);
                        }
                    }

                    if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                        contextMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(LightningActionsTab.this);

            // register ourselves as an HTTP listener
            callbacks.registerHttpListener(LightningActionsTab.this);
        });
    }
    //
    // implement ITab
    //

    @Override
    public String getTabCaption() {
        return "Lightning Actions";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process responses
        if (!messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            // create a new log entry with the message details
            synchronized (actions) {
                if (Utils.isLightningRequest(messageInfo.getRequest(), helpers)) {
                    String decodedMessage = helpers.urlDecode(helpers.getRequestParameter(messageInfo.getRequest(), "message").getValue());
                    actions.addAll(getActions(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo), decodedMessage));
                    int row = actions.size();
                    fireTableRowsInserted(row, row);
                }
            }
        }
    }

    private List<ActionEntry> getActions(int toolFlag, IHttpRequestResponsePersisted requestResponse, String message) {
        List<ActionEntry> output = new ArrayList<>();
        JsonObject jobj = new Gson().fromJson(message, JsonObject.class);
        JsonArray actions = jobj.get("actions").getAsJsonArray();

        IParameter param = helpers.getRequestParameter(requestResponse.getRequest(), "message");
        String host = requestResponse.getHttpService().getProtocol() + "://" + requestResponse.getHttpService().getHost();

        for (int i = 0; i < actions.size(); i++) {
            String descriptor = actions.get(i).getAsJsonObject().get("descriptor").getAsString();
            byte[] request = requestResponse.getRequest();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            JsonObject currentActionJson = actions.get(i).getAsJsonObject();

            //Get simplified request
            try {
                outputStream.write(Arrays.copyOfRange(request, 0, param.getValueStart()));
                outputStream.write(helpers.urlEncode(helpers.stringToBytes("{\"actions\":[")));
                outputStream.write(helpers.urlEncode(helpers.stringToBytes(currentActionJson.toString())));
                outputStream.write(helpers.urlEncode(helpers.stringToBytes("]}")));
                outputStream.write(Arrays.copyOfRange(request, param.getValueEnd(), request.length));
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            //Get parameters
            StringBuilder parameterNames = new StringBuilder();
            Set<Map.Entry<String, JsonElement>> entries = actions.get(i).getAsJsonObject().get("params").getAsJsonObject().entrySet();
            for (Map.Entry<String, JsonElement> entry: entries) {
                parameterNames.append(entry.getKey()).append(", ");
            }
            if(parameterNames.length() > 0)
            {
                parameterNames = new StringBuilder(parameterNames.substring(0, parameterNames.length() - 2));
            }

            output.add(new ActionEntry(toolFlag, requestResponse, descriptor, host, outputStream.toByteArray(), parameterNames.toString()));
        }
        return output;
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount() {
        return actions.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "Tool";
            case 1:
                return "Host";
            case 2:
                return "Action";
            case 3:
                return "Parameters";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ActionEntry actionEntry = actions.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return callbacks.getToolName(actionEntry.tool);
            case 1:
                return actionEntry.host;
            case 2:
                return actionEntry.action;
            case 3:
                return actionEntry.parametersDisplay;
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable {
        Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // show the action entry for the selected row
            ActionEntry actionEntry = actions.get(row);
            requestViewer.setMessage(actionEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(actionEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = actionEntry.requestResponse;
            currentActionEntry = actionEntry;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // extend JPopupMenu
    //
    private class SendMenu extends JPopupMenu {
        private static final String PAYLOAD_TEMPLATE = "{\"actions\":[{\"id\":\"666\",\"descriptor\":\"aura://ApexActionController/ACTION$execute\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"namespace\":\"\",\"classname\":\"\",\"method\":\"\",\"params\":{},\"cacheable\":false,\"isContinuation\":false}}]}";

        SendMenu() {
            JMenuItem sendSimplifiedToRepeater = new JMenuItem("Send simplified request to Repeater");
            sendSimplifiedToRepeater.addActionListener(e -> callbacks.sendToRepeater(
                    currentlyDisplayedItem.getHttpService().getHost(),
                    currentlyDisplayedItem.getHttpService().getPort(),
                    currentlyDisplayedItem.getHttpService().getProtocol().equals("https"),
                    currentActionEntry.simplifiedRequest,
                    null
            ));
            JMenuItem sendSimplifiedToIntruder = new JMenuItem("Send simplified request to Intruder");
            sendSimplifiedToIntruder.addActionListener(e -> callbacks.sendToIntruder(
                    currentlyDisplayedItem.getHttpService().getHost(),
                    currentlyDisplayedItem.getHttpService().getPort(),
                    currentlyDisplayedItem.getHttpService().getProtocol().equals("https"),
                    currentActionEntry.simplifiedRequest
            ));
            JMenuItem sendTemplateToRepeater = new JMenuItem("Send template to Repeater");
            sendTemplateToRepeater.addActionListener(e -> callbacks.sendToRepeater(
                    currentlyDisplayedItem.getHttpService().getHost(),
                    currentlyDisplayedItem.getHttpService().getPort(),
                    currentlyDisplayedItem.getHttpService().getProtocol().equals("https"),
                    makeTemplateRequest(currentActionEntry.simplifiedRequest),
                    null
            ));
            JMenuItem sendTemplateToIntruder = new JMenuItem("Send template to Intruder");
            sendTemplateToIntruder.addActionListener(e -> callbacks.sendToIntruder(
                    currentlyDisplayedItem.getHttpService().getHost(),
                    currentlyDisplayedItem.getHttpService().getPort(),
                    currentlyDisplayedItem.getHttpService().getProtocol().equals("https"),
                    makeTemplateRequest(currentActionEntry.simplifiedRequest)
            ));

            add(sendSimplifiedToRepeater);
            add(sendSimplifiedToIntruder);
            add(new JSeparator());
            add(sendTemplateToRepeater);
            add(sendTemplateToIntruder);
        }

        private byte[] makeTemplateRequest(byte[] originalRequest) {
            IParameter param = helpers.getRequestParameter(originalRequest, "message");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            try {
                outputStream.write(Arrays.copyOfRange(originalRequest, 0, param.getValueStart()));
                outputStream.write(helpers.urlEncode(helpers.stringToBytes(PAYLOAD_TEMPLATE)));
                outputStream.write(Arrays.copyOfRange(originalRequest, param.getValueEnd(), originalRequest.length));
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            return outputStream.toByteArray();
        }
    }
}
