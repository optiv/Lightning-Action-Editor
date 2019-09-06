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

package burp;

import com.optiv.LightningActionEditor.LightningActionsTab;
import com.optiv.LightningActionEditor.LightningMessageEditorFactory;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Lightning Action Editor";
    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // set our extension name
        callbacks.setExtensionName(name);

        // register message editor tab factory
        LightningMessageEditorFactory messageEditor = new LightningMessageEditorFactory(callbacks);
        callbacks.registerMessageEditorTabFactory(messageEditor);

        // register custom tab
        LightningActionsTab actionsTab = new LightningActionsTab(callbacks);

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(name + " started");
    }
}
