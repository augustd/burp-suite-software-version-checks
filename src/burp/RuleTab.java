package burp;

import com.codemagi.burp.MatchRule;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import java.awt.Component;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.regex.Pattern;
import javax.swing.DefaultCellEditor;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

public class RuleTab extends javax.swing.JPanel implements ITab {

    IBurpExtenderCallbacks mCallbacks;
    String tabName;
    PassiveScan scan;

    /**
     * Creates new form BurpSuiteTab
     *
     * @param scan
     * @param tabName
     * @param callbacks For UI Look and Feel
     */
    public RuleTab(PassiveScan scan, String tabName, IBurpExtenderCallbacks callbacks) {

	this.tabName = tabName;
	mCallbacks = callbacks;
	this.scan = scan;

	initComponents();

	mCallbacks.customizeUiComponent(jRadioButtonInScopeRequests);
	mCallbacks.customizeUiComponent(jRadioButtonAllRequests);

	mCallbacks.customizeUiComponent(jCheckBoxProxy);
	mCallbacks.customizeUiComponent(jCheckBoxRepeater);
	mCallbacks.customizeUiComponent(jCheckBoxScanner);
	mCallbacks.customizeUiComponent(jCheckBoxIntruder);
	mCallbacks.customizeUiComponent(jCheckBoxSequencer);
	mCallbacks.customizeUiComponent(jCheckBoxSpider);

	mCallbacks.customizeUiComponent(jTable2);

	jCheckBoxProxy.setBackground(jRadioButtonInScopeRequests.getBackground());
	jCheckBoxRepeater.setBackground(jRadioButtonInScopeRequests.getBackground());
	jCheckBoxScanner.setBackground(jRadioButtonInScopeRequests.getBackground());
	jCheckBoxIntruder.setBackground(jRadioButtonInScopeRequests.getBackground());
	jCheckBoxSequencer.setBackground(jRadioButtonInScopeRequests.getBackground());
	jCheckBoxSpider.setBackground(jRadioButtonInScopeRequests.getBackground());

	buttonGroupDefineScope.add(jRadioButtonInScopeRequests);
	buttonGroupDefineScope.add(jRadioButtonAllRequests);

	restoreSavedSettings();

	loadMatchRules();
    }

    /**
     * Load match rules from a file
     */
    private void loadMatchRules() {
	//load match rules from file
	try {
	    DefaultTableModel model = (DefaultTableModel) jTable2.getModel();

	    //ClassLoader classloader = Thread.currentThread().getContextClassLoader();
	    InputStream is = getClass().getResourceAsStream("match-rules.tab");
	    BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
	    
	    String str;
	    while ((str = reader.readLine()) != null) {
		mCallbacks.printOutput("str: " + str);
		if (str.trim().length() == 0) {
		    continue;
		}

		String[] values = str.split("\\t");
		model.addRow(values);

		mCallbacks.printOutput("Printing file content:");
		mCallbacks.printOutput("regex: " + values[0]);
		mCallbacks.printOutput("group: " + values[1]);
		mCallbacks.printOutput("type: " + values[2]);
		
		Pattern pattern = Pattern.compile(values[0]);
		
		((BurpExtender)scan).addDynamicMatchRule(new MatchRule(
			pattern, 
			new Integer(values[1]), 
			values[2], 
			ScanIssueSeverity.fromName(values[4]),
			ScanIssueConfidence.fromName(values[3]))
		);
	    }

	} catch (Exception e) {
	    OutputStream error = mCallbacks.getStderr();
	    e.printStackTrace(new PrintStream(error));
	}
    }
    
    /**
     * Restores any found saved settings
     *
     * @return
     */
    private void restoreSavedSettings() {
	boolean proxySel = false;
	boolean repeaterSel = false;
	boolean scannerSel = false;
	boolean intruderSel = false;
	boolean sequencerSel = false;
	boolean spiderSel = false;
	boolean scopeAllSel = false;

	if (mCallbacks.loadExtensionSetting("O_TOOL_PROXY") != null) {
	    proxySel = getSetting("O_TOOL_PROXY");
	}
	if (mCallbacks.loadExtensionSetting("O_TOOL_REPEATER") != null) {
	    repeaterSel = getSetting("O_TOOL_REPEATER");
	}
	if (mCallbacks.loadExtensionSetting("O_TOOL_SCANNER") != null) {
	    scannerSel = getSetting("O_TOOL_SCANNER");
	}
	if (mCallbacks.loadExtensionSetting("O_TOOL_INTRUDER") != null) {
	    intruderSel = getSetting("O_TOOL_INTRUDER");
	}
	if (mCallbacks.loadExtensionSetting("O_TOOL_SEQUENCER") != null) {
	    sequencerSel = getSetting("O_TOOL_SEQUENCER");
	}
	if (mCallbacks.loadExtensionSetting("O_TOOL_SPIDER") != null) {
	    spiderSel = getSetting("O_TOOL_SPIDER");
	}
	if (mCallbacks.loadExtensionSetting("O_SCOPE") != null) {
	    scopeAllSel = getSetting("O_SCOPE");
	}
	jCheckBoxProxy.setSelected(proxySel);
	jCheckBoxRepeater.setSelected(repeaterSel);
	jCheckBoxScanner.setSelected(scannerSel);
	jCheckBoxIntruder.setSelected(intruderSel);
	jCheckBoxSequencer.setSelected(sequencerSel);
	jCheckBoxSpider.setSelected(spiderSel);
	jRadioButtonAllRequests.setSelected(scopeAllSel);
    }

    private boolean getSetting(String name) {
	if (name.equals("O_SCOPE") && mCallbacks.loadExtensionSetting(name).equals("ALL") == true) {
	    return true;
	} else {
	    return mCallbacks.loadExtensionSetting(name).equals("ENABLED") == true;
	}
    }

    protected void saveSettings() {
	// Clear settings
	mCallbacks.saveExtensionSetting("O_TOOL_PROXY", null);
	mCallbacks.saveExtensionSetting("O_TOOL_REPEATER", null);
	mCallbacks.saveExtensionSetting("O_TOOL_SCANNER", null);
	mCallbacks.saveExtensionSetting("O_TOOL_INTRUDER", null);
	mCallbacks.saveExtensionSetting("O_TOOL_SEQUENCER", null);
	mCallbacks.saveExtensionSetting("O_TOOL_SPIDER", null);
	mCallbacks.saveExtensionSetting("O_SCOPE", null);
	// Set any selected checkboxes in settings
	if (jCheckBoxProxy.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_TOOL_PROXY", "ENABLED");
	}
	if (jCheckBoxRepeater.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_TOOL_REPEATER", "ENABLED");
	}
	if (jCheckBoxScanner.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_TOOL_SCANNER", "ENABLED");
	}
	if (jCheckBoxIntruder.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_TOOL_INTRUDER", "ENABLED");
	}
	if (jCheckBoxSequencer.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_TOOL_SEQUENCER", "ENABLED");
	}
	if (jCheckBoxSpider.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_TOOL_SPIDER", "ENABLED");
	}
	if (jRadioButtonAllRequests.isSelected()) {
	    mCallbacks.saveExtensionSetting("O_SCOPE", "ALL");
	}
    }

    /**
     * Returns true if all response times should be calculated
     *
     * @return
     */
    public boolean processAllRequests() {
	return jRadioButtonAllRequests.isSelected();
    }

    /**
     * Returns true if the requested tool is selected in the GUI
     *
     * @param tool
     * @return
     */
    public boolean isToolSelected(int tool) {
	boolean selected = false;
	switch (tool) {
	    case IBurpExtenderCallbacks.TOOL_PROXY:
		selected = jCheckBoxProxy.isSelected();
		break;
	    case IBurpExtenderCallbacks.TOOL_REPEATER:
		selected = jCheckBoxRepeater.isSelected();
		break;
	    case IBurpExtenderCallbacks.TOOL_SCANNER:
		selected = jCheckBoxScanner.isSelected();
		break;
	    case IBurpExtenderCallbacks.TOOL_INTRUDER:
		selected = jCheckBoxIntruder.isSelected();
		break;
	    case IBurpExtenderCallbacks.TOOL_SEQUENCER:
		selected = jCheckBoxSequencer.isSelected();
		break;
	    case IBurpExtenderCallbacks.TOOL_SPIDER:
		selected = jCheckBoxSpider.isSelected();
		break;
	    case IBurpExtenderCallbacks.TOOL_TARGET:
		break;
	    default:
		break;
	}
	return selected;
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroupDefineScope = new javax.swing.ButtonGroup();
        buttonGroupChars = new javax.swing.ButtonGroup();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jLabel1 = new javax.swing.JLabel();
        jRadioButtonInScopeRequests = new javax.swing.JRadioButton();
        jRadioButtonAllRequests = new javax.swing.JRadioButton();
        jCheckBoxProxy = new javax.swing.JCheckBox();
        jCheckBoxRepeater = new javax.swing.JCheckBox();
        jCheckBoxScanner = new javax.swing.JCheckBox();
        jCheckBoxIntruder = new javax.swing.JCheckBox();
        jCheckBoxSequencer = new javax.swing.JCheckBox();
        jCheckBoxSpider = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTable2 = new javax.swing.JTable();
        jLabel2 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jTextField2 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"joebob", null, null},
                {"jimbob", null, null},
                {null, null, null},
                {null, null, null}
            },
            new String [] {
                "Regex", "Type", "Severity"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.String.class, java.lang.Integer.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        jScrollPane1.setViewportView(jTable1);

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(229, 137, 0));
        jLabel1.setText("Tools Scope");

        jRadioButtonInScopeRequests.setSelected(true);
        jRadioButtonInScopeRequests.setText("In scope requests");

        jRadioButtonAllRequests.setText("All requests");

        jCheckBoxProxy.setSelected(true);
        jCheckBoxProxy.setText("Proxy");

        jCheckBoxRepeater.setSelected(true);
        jCheckBoxRepeater.setText("Repeater");

        jCheckBoxScanner.setSelected(true);
        jCheckBoxScanner.setText("Scanner");
        jCheckBoxScanner.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxScannerActionPerformed(evt);
            }
        });

        jCheckBoxIntruder.setSelected(true);
        jCheckBoxIntruder.setText("Intruder");
        jCheckBoxIntruder.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxIntruderActionPerformed(evt);
            }
        });

        jCheckBoxSequencer.setSelected(true);
        jCheckBoxSequencer.setText("Sequencer");
        jCheckBoxSequencer.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxSequencerActionPerformed(evt);
            }
        });

        jCheckBoxSpider.setSelected(true);
        jCheckBoxSpider.setText("Spider");

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(229, 137, 0));
        jLabel3.setText("URL Scope");

        jLabel4.setText("Select the tools that this extenstion will act on:");

        jLabel5.setText("Select the configuration this extenstion will act on:");

        jTable2.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Regex", "Group", "Type", "Severity", "Confidence"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.Integer.class, java.lang.String.class, java.lang.String.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        TableColumn severityColumn = jTable2.getColumnModel().getColumn(3);
        severityColumn.setCellEditor(new DefaultCellEditor(ScanIssueSeverity.getComboBox()));

        TableColumn confidenceColumn = jTable2.getColumnModel().getColumn(4);
        confidenceColumn.setCellEditor(new DefaultCellEditor(ScanIssueConfidence.getComboBox()));
        jScrollPane2.setViewportView(jTable2);

        jLabel2.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(229, 137, 0));
        jLabel2.setText("Match Rules");

        jLabel6.setText("Load match rules from URL: ");

        jTextField2.setText("jTextField2");
        jTextField2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField2ActionPerformed(evt);
            }
        });

        jButton1.setText("LOAD");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel4)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(jLabel5)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jCheckBoxProxy)
                                    .addComponent(jCheckBoxRepeater)
                                    .addComponent(jCheckBoxScanner))
                                .addGap(22, 22, 22)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jCheckBoxSpider)
                                    .addComponent(jCheckBoxSequencer)
                                    .addComponent(jCheckBoxIntruder))))
                        .addComponent(jRadioButtonInScopeRequests)
                        .addComponent(jRadioButtonAllRequests))
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addComponent(jLabel6)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 380, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton1))
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(84, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(jLabel6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jCheckBoxProxy)
                        .addComponent(jCheckBoxIntruder))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jButton1)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jCheckBoxRepeater)
                            .addComponent(jCheckBoxSequencer))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jCheckBoxScanner)
                            .addComponent(jCheckBoxSpider))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jRadioButtonInScopeRequests)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jRadioButtonAllRequests))
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 47, Short.MAX_VALUE))
        );

        jLabel1.getAccessibleContext().setAccessibleDescription("");
        jLabel5.getAccessibleContext().setAccessibleName("Select the configuration this extenstion applies to:");
    }// </editor-fold>//GEN-END:initComponents

    private void jCheckBoxIntruderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxIntruderActionPerformed
	// TODO add your handling code here:
    }//GEN-LAST:event_jCheckBoxIntruderActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
	//read value from text field
	
	//issue request to URL
	
	//parse text file 
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jTextField2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField2ActionPerformed
	// TODO add your handling code here:
    }//GEN-LAST:event_jTextField2ActionPerformed

    private void jCheckBoxScannerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxScannerActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jCheckBoxScannerActionPerformed

    private void jCheckBoxSequencerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxSequencerActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jCheckBoxSequencerActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroupChars;
    private javax.swing.ButtonGroup buttonGroupDefineScope;
    private javax.swing.JButton jButton1;
    private javax.swing.JCheckBox jCheckBoxIntruder;
    private javax.swing.JCheckBox jCheckBoxProxy;
    private javax.swing.JCheckBox jCheckBoxRepeater;
    private javax.swing.JCheckBox jCheckBoxScanner;
    private javax.swing.JCheckBox jCheckBoxSequencer;
    private javax.swing.JCheckBox jCheckBoxSpider;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JRadioButton jRadioButtonAllRequests;
    private javax.swing.JRadioButton jRadioButtonInScopeRequests;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTable jTable1;
    private javax.swing.JTable jTable2;
    private javax.swing.JTextField jTextField2;
    // End of variables declaration//GEN-END:variables

    @Override
    public String getTabCaption() {
	return tabName;
    }

    @Override
    public Component getUiComponent() {
	return this;
    }

}
