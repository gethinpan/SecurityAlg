package edu.seu.app.panel;

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
//        JPanel panelDown = new JPanel();
//        panelDown.setBackground(UIConstants.TOOL_BAR_BACK_COLOR);
//        panelDown.setLayout(new BorderLayout(0, 0));

        buttonKeyParameter = new MyIconButton(UIConstants.ICON_KEY_PARAMETER, UIConstants.ICON_KEY_PARAMETER,
                UIConstants.ICON_KEY_PARAMETER, "设置加密参数");
        buttonSend = new MyIconButton(UIConstants.ICON_SEND, UIConstants.ICON_SEND,
                UIConstants.ICON_SEND, "加密发送消息");
        buttonReceive = new MyIconButton(UIConstants.ICON_RECEIVE, UIConstants.ICON_RECEIVE,
                UIConstants.ICON_RECEIVE, "接收验证消息");

        panelUp.add(buttonKeyParameter);
        panelUp.add(buttonSend);
        panelUp.add(buttonReceive);
    }

    /**
     * 为各按钮添加事件动作监听
     */
    private void addListener() {
        buttonKeyParameter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonKeyParameter.setIcon(UIConstants.ICON_KEY_PARAMETER);
                buttonSend.setIcon(UIConstants.ICON_SEND);
                buttonReceive.setIcon(UIConstants.ICON_RECEIVE);

            }
        });
    }
}
