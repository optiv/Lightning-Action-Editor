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

import burp.IExtensionHelpers;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

class Utils {

    public static String prettyPrintJson(String data) {
        try {
            String json;
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
            JsonParser jp = new JsonParser();
            JsonElement je = jp.parse(data);
            json = gson.toJson(je);
            return json;
        } catch (Exception ex) {
            return data;
        }
    }

    public static String unPrettyPrintJson(String data) {
        try {
            String json;
            Gson gson = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
            JsonParser jp = new JsonParser();
            JsonElement je = jp.parse(data);
            json = gson.toJson(je);
            return json;
        } catch (Exception ex) {
            return data;
        }
    }

    public static boolean isLightningRequest(byte[] request, IExtensionHelpers helpers) {
        return null != helpers.getRequestParameter(request, "message") &&
                null != helpers.getRequestParameter(request, "aura.context") &&
                null != helpers.getRequestParameter(request, "aura.token");
    }
}
