package edu.seu.app.panel;

import edu.seu.app.AppMainWindow;
import edu.seu.app.MyIconButton;
import edu.seu.app.UIConstants;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import static edu.seu.app.AppMainWindow.securityUtil;

public class SendPanel extends JPanel {
    private JTextArea messageArea;
    private JButton sendButton;

    public SendPanel() {
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

    /**
     * 上部面板
     */
    private JPanel getUpPanel() {
        JPanel panelUp = new JPanel();
        panelUp.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelUp.setLayout(new FlowLayout(FlowLayout.LEFT, UIConstants.MAIN_H_GAP, 5));

        JLabel labelTitle = new JLabel("加密发送");
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

        JLabel messageLabel = new JLabel("请在以下区域输入需要加密的内容：");
        messageLabel.setFont(UIConstants.FONT_NORMAL);
        messageLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        messageLabel.setBounds(25, 20, 300, 20);

        Border border = BorderFactory.createEtchedBorder();
        messageArea = new JTextArea(40, 40);
        messageArea.setLineWrap(true);
        messageArea.setFont(UIConstants.FONT_NORMAL);
        messageArea.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        messageArea.setBounds(25, 50, 770, 430);
        messageArea.setBorder(border);

        panelCenter.add(messageLabel);
        panelCenter.add(messageArea);

        return panelCenter;
    }

    /**
     * 底部面板
     */
    private JPanel getDownPanel() {
        JPanel panelDown = new JPanel();
        panelDown.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelDown.setLayout(new FlowLayout(FlowLayout.RIGHT, UIConstants.MAIN_H_GAP, 15));

        sendButton = new MyIconButton(UIConstants.ICON_SEND_BUTTON, UIConstants.ICON_SEND_BUTTON_ENABLE,
                UIConstants.ICON_SEND_BUTTON_DISABLE, "");
        panelDown.add(sendButton);

        return panelDown;
    }

    private void addListener() {
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String msg = messageArea.getText();
                AppMainWindow.securityUtil.sendProcess(msg);
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
                frame.add(new SendPanel());
                frame.setVisible(true);
            }
        });
    }
}
