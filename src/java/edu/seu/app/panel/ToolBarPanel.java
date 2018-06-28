package edu.seu.app.panel;

import edu.seu.app.AppMainWindow;
import edu.seu.app.MyIconButton;
import edu.seu.app.UIConstants;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ToolBarPanel extends JPanel {
    private static MyIconButton buttonKeyParameter;
    private static MyIconButton buttonSend;
    private static MyIconButton buttonReceive;
    private static MyIconButton buttonSetting;

    public ToolBarPanel() {
        initialize();
        addButton();
        addListener();
    }

    private void initialize() {
        Dimension preferredSize = new Dimension(48, UIConstants.MAIN_WINDOW_HEIGHT);
        this.setPreferredSize(preferredSize);
        this.setMaximumSize(preferredSize);
        this.setMinimumSize(preferredSize);
        this.setBackground(UIConstants.TOOL_BAR_BACK_COLOR);
        this.setLayout(new GridLayout(2,1));
    }

    /**
     * 添加工具按钮
     */
    private void addButton() {
        JPanel panelUp = new JPanel();
        panelUp.setBackground(UIConstants.TOOL_BAR_BACK_COLOR);
        panelUp.setLayout(new FlowLayout(-2, -2, -4));
        JPanel panelDown = new JPanel();
        panelDown.setBackground(UIConstants.TOOL_BAR_BACK_COLOR);
        panelDown.setLayout(new BorderLayout(0, 0));

        buttonKeyParameter = new MyIconButton(UIConstants.ICON_KEY_PARAMETER, UIConstants.ICON_KEY_PARAMETER_ENABLE,
                UIConstants.ICON_KEY_PARAMETER, "设置加密参数");
        buttonSend = new MyIconButton(UIConstants.ICON_SEND, UIConstants.ICON_SEND_ENABLE,
                UIConstants.ICON_SEND, "加密发送消息");
        buttonReceive = new MyIconButton(UIConstants.ICON_RECEIVE, UIConstants.ICON_RECEIVE_ENABLE,
                UIConstants.ICON_RECEIVE, "接收验证消息");
        buttonSetting = new MyIconButton(UIConstants.ICON_SETTING, UIConstants.ICON_SETTING_ENABLE,
                UIConstants.ICON_SETTING, "设置");

        panelUp.add(buttonKeyParameter);
        panelUp.add(buttonSend);
        panelUp.add(buttonReceive);

        panelDown.add(buttonSetting, BorderLayout.SOUTH);

        this.add(panelUp);
        this.add(panelDown);
    }

    /**
     * 为各按钮添加事件动作监听
     */
    private void addListener() {
        buttonKeyParameter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonKeyParameter.setIcon(UIConstants.ICON_KEY_PARAMETER_ENABLE);
                buttonSend.setIcon(UIConstants.ICON_SEND);
                buttonReceive.setIcon(UIConstants.ICON_RECEIVE);
                buttonSetting.setIcon(UIConstants.ICON_SETTING);

                AppMainWindow.mainPanelCenter.removeAll();
                AppMainWindow.mainPanelCenter.add(AppMainWindow.keyParameterPanel, BorderLayout.CENTER);

                AppMainWindow.mainPanelCenter.updateUI();
            }
        });

        buttonSend.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonKeyParameter.setIcon(UIConstants.ICON_KEY_PARAMETER);
                buttonSend.setIcon(UIConstants.ICON_SEND_ENABLE);
                buttonReceive.setIcon(UIConstants.ICON_RECEIVE);
                buttonSetting.setIcon(UIConstants.ICON_SETTING);

                AppMainWindow.mainPanelCenter.removeAll();
                AppMainWindow.mainPanelCenter.add(AppMainWindow.sendPanel, BorderLayout.CENTER);

                AppMainWindow.mainPanelCenter.updateUI();
            }
        });

        buttonReceive.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonKeyParameter.setIcon(UIConstants.ICON_KEY_PARAMETER);
                buttonSend.setIcon(UIConstants.ICON_SEND);
                buttonReceive.setIcon(UIConstants.ICON_RECEIVE_ENABLE);
                buttonSetting.setIcon(UIConstants.ICON_SETTING);

                AppMainWindow.mainPanelCenter.removeAll();
                AppMainWindow.mainPanelCenter.add(AppMainWindow.receivePanel, BorderLayout.CENTER);

                AppMainWindow.mainPanelCenter.updateUI();

                AppMainWindow.receivePanel.getReceiveArea().
                        setText(AppMainWindow.securityUtil.senderMessage);
            }
        });

        buttonSetting.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonKeyParameter.setIcon(UIConstants.ICON_KEY_PARAMETER);
                buttonSend.setIcon(UIConstants.ICON_SEND);
                buttonReceive.setIcon(UIConstants.ICON_RECEIVE);
                buttonSetting.setIcon(UIConstants.ICON_SETTING_ENABLE);

                AppMainWindow.mainPanelCenter.removeAll();
                AppMainWindow.mainPanelCenter.add(AppMainWindow.settingPanel, BorderLayout.CENTER);

                AppMainWindow.mainPanelCenter.updateUI();
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
                frame.setLayout(new BorderLayout());
                frame.add(new ToolBarPanel(), BorderLayout.WEST);
                frame.setVisible(true);
            }
        });
    }
}
