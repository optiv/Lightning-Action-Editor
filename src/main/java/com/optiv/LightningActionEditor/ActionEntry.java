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

import burp.IHttpRequestResponsePersisted;

class ActionEntry {
    final int tool;
    final IHttpRequestResponsePersisted requestResponse;
    final String action;
    final String host;
    final byte[] simplifiedRequest;
    final String parametersDisplay;

    ActionEntry(int tool, IHttpRequestResponsePersisted requestResponse, String action, String host, byte[] simplifiedRequest, String parametersDisplay) {
        this.tool = tool;
        this.requestResponse = requestResponse;
        this.action = action;
        this.host = host;
        this.simplifiedRequest = simplifiedRequest;
        this.parametersDisplay = parametersDisplay;
    }
}
