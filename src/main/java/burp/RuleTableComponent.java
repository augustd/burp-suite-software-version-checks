package burp;

import com.codemagi.burp.MatchRule;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.DefaultCellEditor;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

public class RuleTableComponent extends javax.swing.JPanel {

    IBurpExtenderCallbacks mCallbacks;
    PassiveScan scan;

    public static final String DEFAULT_URL = "https://raw.githubusercontent.com/augustd/burp-suite-software-version-checks/master/src/burp/match-rules.tab";
    public static final String SETTING_URL = "SETTING_URL";
    
    /**
     * Creates new form BurpSuiteTab
     *
     * @param scan
     * @param callbacks For UI Look and Feel
     */
    public RuleTableComponent(final PassiveScan scan, IBurpExtenderCallbacks callbacks) {

	mCallbacks = callbacks;
	this.scan = scan;

	initComponents();

	mCallbacks.customizeUiComponent(rules);
        
        //restore saved settings 
        restoreSettings();
        
	//load match rules from GitHub
        loadMatchRules(urlTextField.getText()); 

        //add a listener for changes to the table model
        final DefaultTableModel model = (DefaultTableModel)rules.getModel();
        model.addTableModelListener(new TableModelListener() {
            public void tableChanged(TableModelEvent e) {
                if (TableModelEvent.UPDATE == e.getType()) {
                    mCallbacks.printOutput(e.toString());
                    int row = e.getFirstRow();
                    int column = e.getColumn();
                    mCallbacks.printOutput("row: " + row + " column: " + column + " value: " + model.getValueAt(row, column));
                    MatchRule rule = scan.getMatchRule(row);
                    mCallbacks.printOutput("rule 1: " + rule); 
                    if (rule == null) {
                        rule = new MatchRule(Pattern.compile("."), 1, "", ScanIssueSeverity.LOW, ScanIssueConfidence.CERTAIN);
                        scan.addMatchRule(rule);
                    }
                    mCallbacks.printOutput("rule 2: " + rule); 
                    
                    switch (column) { 
                        case 0: 
                            mCallbacks.printOutput("new pattern: " + (String)model.getValueAt(row, column));
                            rule.setPattern(Pattern.compile((String)model.getValueAt(row, column)));
                            break;
                        case 1:
                            rule.setMatchGroup((Integer)model.getValueAt(row, column));
                            break;
                       case 2:
                            rule.setType((String)model.getValueAt(row, column));
                            break;
                        case 3:
                            rule.setSeverity(ScanIssueSeverity.fromName((String)model.getValueAt(row, column)));
                            break;
                        case 4:
                            rule.setConfidence(ScanIssueConfidence.fromName((String)model.getValueAt(row, column)));
                            break;
                    }
                }
            }
        });
    }

    /**
     * Load match rules from a file
     */
    private boolean loadMatchRules(String url) {
	//load match rules from file
	try {
	    
	    DefaultTableModel model = (DefaultTableModel)rules.getModel();

	    //read match rules from the stream
	    InputStream is = new URL(url).openStream();
	    BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
	    
	    String str;
	    while ((str = reader.readLine()) != null) {
		mCallbacks.printOutput("str: " + str);
		if (str.trim().length() == 0) {
		    continue;
		}

		String[] values = str.split("\\t");
		model.addRow(values);

                try {
                    Pattern pattern = Pattern.compile(values[0]);

                    scan.addMatchRule(new MatchRule(
                            pattern, 
                            new Integer(values[1]), 
                            values[2], 
                            ScanIssueSeverity.fromName(values[3]),
                            ScanIssueConfidence.fromName(values[4]))
                    );
                } catch (PatternSyntaxException pse) {
                    mCallbacks.printError("Unable to compile pattern: " + values[0] + " for: " + values[2]);
                    scan.printStackTrace(pse);
                }
	    }
            
            return true;

	} catch (IOException e) {
	    OutputStream error = mCallbacks.getStderr();
	    e.printStackTrace(new PrintStream(error));
	} catch (NumberFormatException e) {
	    OutputStream error = mCallbacks.getStderr();
	    e.printStackTrace(new PrintStream(error));
	}
        
        return false;
    }
    
    /**
     * Save all configured settings
     */
    public void saveSettings() {
        mCallbacks.printOutput("Saving settings...");
        
        // Clear settings
        mCallbacks.saveExtensionSetting(scan.getSettingsNamespace() + SETTING_URL, null);
        
        // Store settings
        mCallbacks.printOutput("Saving URL: " + urlTextField.getText());
        mCallbacks.saveExtensionSetting(scan.getSettingsNamespace() + SETTING_URL, urlTextField.getText());
    }
    
    /**
     * Restores any found saved settings
     */
    public void restoreSettings() {
        mCallbacks.printOutput("Restoring settings...");
        
        String settingUrl = mCallbacks.loadExtensionSetting(scan.getSettingsNamespace() + SETTING_URL);
        mCallbacks.printOutput("Loaded URL: " + settingUrl);
        if (settingUrl != null) {
            urlTextField.setText(settingUrl);
            //extender.setFormUrl(settingUrl);
        }
    }
    
    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane2 = new javax.swing.JScrollPane();
        rules = new javax.swing.JTable();
        jLabel2 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        urlTextField = new javax.swing.JTextField();
        loadBtn = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        addBtn = new javax.swing.JButton();
        removeBtn = new javax.swing.JButton();
        resetButton = new javax.swing.JButton();

        rules.setModel(new javax.swing.table.DefaultTableModel(
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
        TableColumn severityColumn = rules.getColumnModel().getColumn(3);
        severityColumn.setCellEditor(new DefaultCellEditor(ScanIssueSeverity.getComboBox()));

        TableColumn confidenceColumn = rules.getColumnModel().getColumn(4);
        confidenceColumn.setCellEditor(new DefaultCellEditor(ScanIssueConfidence.getComboBox()));
        jScrollPane2.setViewportView(rules);

        jLabel2.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(229, 137, 0));
        jLabel2.setText("Match Rules");

        jLabel6.setText("Match rules use regular epressions to flag software version numbers in server responses");

        urlTextField.setText("https://raw.githubusercontent.com/augustd/burp-suite-software-version-checks/master/src/burp/match-rules.tab");
        urlTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                urlTextFieldActionPerformed(evt);
            }
        });

        loadBtn.setText("Load");
        loadBtn.setIgnoreRepaint(true);
        loadBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadBtnActionPerformed(evt);
            }
        });

        jLabel7.setText("Load rules from URL: ");

        addBtn.setText("Add");
        addBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addBtnActionPerformed(evt);
            }
        });

        removeBtn.setText("Remove");
        removeBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeBtnActionPerformed(evt);
            }
        });

        resetButton.setText("Reset");
        resetButton.setToolTipText("Reload default match rules from GitHub");
        resetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                resetButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel6)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(addBtn)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(removeBtn)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel7)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(urlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 406, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(loadBtn)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(resetButton)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(urlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7)
                    .addComponent(loadBtn)
                    .addComponent(resetButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(addBtn)
                    .addComponent(removeBtn))
                .addContainerGap(12, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void loadBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadBtnActionPerformed
	//read value from text field
	String url = urlTextField.getText();
	
	//issue request to URL
	boolean success = loadMatchRules(url);
        if (success) saveSettings();
    }//GEN-LAST:event_loadBtnActionPerformed

    private void urlTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_urlTextFieldActionPerformed
	// TODO add your handling code here:
    }//GEN-LAST:event_urlTextFieldActionPerformed

    private void addBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addBtnActionPerformed
        DefaultTableModel model = (DefaultTableModel)rules.getModel();
        model.addRow(new Object[]{"", 1, "", "Low", "Certain"});
    }//GEN-LAST:event_addBtnActionPerformed

    private void removeBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeBtnActionPerformed
        DefaultTableModel model = (DefaultTableModel)rules.getModel();
        int[] rows = rules.getSelectedRows();
        for (int i = 0; i < rows.length; i++) {
            model.removeRow(rows[i] - i);
            scan.removeMatchRule(rows[i] - i);
        }
    }//GEN-LAST:event_removeBtnActionPerformed

    private void resetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_resetButtonActionPerformed
        //clear the existing values from the table    
        DefaultTableModel model = (DefaultTableModel) rules.getModel();
        model.setRowCount(0);
        
        //remove existing match rules from the scan
        scan.clearMatchRules();

        //load the defaults
        urlTextField.setText(DEFAULT_URL);
        loadMatchRules(DEFAULT_URL);
        
        saveSettings();
    }//GEN-LAST:event_resetButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addBtn;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton loadBtn;
    private javax.swing.JButton removeBtn;
    private javax.swing.JButton resetButton;
    private javax.swing.JTable rules;
    private javax.swing.JTextField urlTextField;
    // End of variables declaration//GEN-END:variables

}
