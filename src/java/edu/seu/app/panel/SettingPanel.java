package edu.seu.app.panel;

import edu.seu.app.MyIconButton;
import edu.seu.app.UIConstants;

import javax.swing.*;
import java.awt.*;

public class SettingPanel extends JPanel {

    public SettingPanel() {
        initialize();
        addComponent();
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

        JLabel labelTitle = new JLabel("关于");
        labelTitle.setFont(UIConstants.FONT_TITLE);
        labelTitle.setForeground(UIConstants.TOOL_BAR_BACK_COLOR);
        panelUp.add(labelTitle);

        return panelUp;
    }

    /**
     * 中部面板
     *
     * @return
     */
    private JPanel getCenterPanel() {
        // 中间面板
        JPanel panelCenter = new JPanel();
        panelCenter.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelCenter.setLayout(new GridLayout(3, 1));

        // 图标、版本Grid
        JPanel panelGridIcon = new JPanel();
        panelGridIcon.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelGridIcon.setLayout(new FlowLayout(FlowLayout.LEFT, UIConstants.MAIN_H_GAP, 0));

        // 初始化组件
        MyIconButton icon = new MyIconButton(UIConstants.ICON_DATA_ENC, UIConstants.ICON_DATA_ENC,
                UIConstants.ICON_DATA_ENC, "");
        JLabel labelName = new JLabel(UIConstants.MAIN_WINDOW_TITLE);
        JLabel labelVersion = new JLabel(UIConstants.VERSION);

        // 字体
        labelName.setFont(UIConstants.FONT_NORMAL);
        labelVersion.setFont(UIConstants.FONT_NORMAL);

        // 大小
        Dimension size = new Dimension(200, 30);
        labelName.setPreferredSize(size);
        labelVersion.setPreferredSize(size);

        // 组合元素
        panelGridIcon.add(icon);
        panelGridIcon.add(labelName);
        panelGridIcon.add(labelVersion);

        // 建议帮助 Grid
        JPanel panelGridHelp = new JPanel();
        panelGridHelp.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelGridHelp.setLayout(new FlowLayout(FlowLayout.LEFT, UIConstants.MAIN_H_GAP, 0));

        // 初始化组件
        JLabel labelAdvice = new JLabel("反馈建议");
        JLabel labelHelp = new JLabel("帮助");

        // 字体
        labelAdvice.setFont(UIConstants.FONT_NORMAL);
        labelHelp.setFont(UIConstants.FONT_NORMAL);

        // 大小
        labelAdvice.setPreferredSize(UIConstants.LABLE_SIZE);
        labelHelp.setPreferredSize(UIConstants.LABLE_SIZE);

        // 组合元素
        panelGridHelp.add(labelAdvice);
        panelGridHelp.add(labelHelp);

        panelCenter.add(panelGridIcon);
        // panelCenter.add(panelGridHelp);
        return panelCenter;
    }

    /**
     * 底部面板
     *
     * @return
     */
    private JPanel getDownPanel() {
        JPanel panelDown = new JPanel();
        panelDown.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelDown.setLayout(new FlowLayout(FlowLayout.LEFT, UIConstants.MAIN_H_GAP, 15));

        JLabel labelInfo = new JLabel("Copyright © 2018 | All Rights Reserved. | https://github.com/gethinpan");
        labelInfo.setFont(UIConstants.FONT_NORMAL);
        labelInfo.setForeground(Color.gray);

        panelDown.add(labelInfo);

        return panelDown;
    }
}
