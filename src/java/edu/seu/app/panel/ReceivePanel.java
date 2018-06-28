package edu.seu.app.panel;

import edu.seu.app.AppMainWindow;
import edu.seu.app.MyIconButton;
import edu.seu.app.UIConstants;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

public class ReceivePanel extends JPanel {
    private JTextArea receiveArea;
    private JTextArea plaintextArea;
    private MyIconButton decryptButton;
    private MyIconButton authButton;

    public ReceivePanel() {
        initialize();
        addComponent();
        addListener();
    }

    private void initialize() {
        this.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        this.setLayout(new BorderLayout());
    }

    private void addComponent() {
        this.add(getUpPanel(), BorderLayout.NORTH);
        this.add(getCenterPanel(), BorderLayout.CENTER);
        this.add(getDownPanel(), BorderLayout.SOUTH);
    }

    public JTextArea getReceiveArea() {
        return receiveArea;
    }

    /**
     * 上部面板
     */
    private JPanel getUpPanel() {
        JPanel panelUp = new JPanel();
        panelUp.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelUp.setLayout(new FlowLayout(FlowLayout.LEFT, UIConstants.MAIN_H_GAP, 5));

        JLabel labelTitle = new JLabel("解密认证");
        labelTitle.setFont(UIConstants.FONT_TITLE);
        labelTitle.setForeground(UIConstants.TOOL_BAR_BACK_COLOR);
        panelUp.add(labelTitle);

        return panelUp;
    }

    /**
     * 中部面板
     */
    private JPanel getCenterPanel() {
        JPanel panelCenter = new JPanel();
        panelCenter.setBounds(25, 20, 800, 600);
        panelCenter.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelCenter.setLayout(null);

        JLabel ciphertextLabel = new JLabel("接收的密文如下：");
        ciphertextLabel.setFont(UIConstants.FONT_NORMAL);
        ciphertextLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        ciphertextLabel.setBounds(25, 20, 300, 20);

        Border border1 = BorderFactory.createEtchedBorder();
        receiveArea = new JTextArea(40, 40);
        receiveArea.setLineWrap(true);
        receiveArea.setFont(UIConstants.FONT_NORMAL);
        receiveArea.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        receiveArea.setBounds(25, 50, 375, 430);
        receiveArea.setLineWrap(true);
        receiveArea.setBorder(border1);
        JScrollPane scroll1 = new JScrollPane();
        scroll1.setBounds(25, 50, 375, 430);
        scroll1.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll1.setViewportView(receiveArea);

        JLabel plaintextLabel = new JLabel("解密后明文如下：");
        plaintextLabel.setFont(UIConstants.FONT_NORMAL);
        plaintextLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        plaintextLabel.setBounds(420, 20, 300, 20);

        Border border2 = BorderFactory.createEtchedBorder();
        plaintextArea = new JTextArea(40, 40);
        plaintextArea.setLineWrap(true);
        plaintextArea.setFont(UIConstants.FONT_NORMAL);
        plaintextArea.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        plaintextArea.setBounds(420, 50, 375, 430);
        plaintextArea.setLineWrap(true);
        plaintextArea.setBorder(border2);
        JScrollPane scroll2 = new JScrollPane();
        scroll2.setBounds(420, 50, 375, 430);
        scroll2.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll2.setViewportView(plaintextArea);

        panelCenter.add(ciphertextLabel);
        panelCenter.add(scroll1);
        panelCenter.add(plaintextLabel);
        panelCenter.add(scroll2);

        return panelCenter;
    }

    /**
     * 底部面板
     */
    private JPanel getDownPanel() {
        JPanel panelDown = new JPanel();
        panelDown.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelDown.setLayout(new FlowLayout(FlowLayout.RIGHT, UIConstants.MAIN_H_GAP, 15));

        decryptButton = new MyIconButton(UIConstants.ICON_DECRYPT_BUTTON, UIConstants.ICON_DECRYPT_BUTTON_ENABLE,
                UIConstants.ICON_DECRYPT_BUTTON_DISABLE, "");
        authButton = new MyIconButton(UIConstants.ICON_AUTH_BUTTON, UIConstants.ICON_AUTH_BUTTON_ENABLE,
                UIConstants.ICON_AUTH_BUTTON_DISABLE, "");

        panelDown.add(decryptButton);
        panelDown.add(authButton);

        return panelDown;
    }

    private void addListener() {
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String msg = receiveArea.getText();
                String result = AppMainWindow.securityUtil.receiverDecrypt(msg);
                plaintextArea.setText(result);
            }
        });

        authButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String msg = receiveArea.getText();
                plaintextArea.append(AppMainWindow.securityUtil.receiverVerify(msg));
            }
        });
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame();
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.setBounds(UIConstants.MAIN_WINDOW_X, UIConstants.MAIN_WINDOW_Y,
                        UIConstants.MAIN_WINDOW_WIDTH, UIConstants.MAIN_WINDOW_HEIGHT);
                frame.add(new ReceivePanel());
                frame.setVisible(true);
            }
        });
    }
}
