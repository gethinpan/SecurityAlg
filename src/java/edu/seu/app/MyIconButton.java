package edu.seu.app;

import javax.swing.*;
import java.awt.*;

public class MyIconButton extends JButton {
    private ImageIcon iconEnable, iconDisable;
    private String tip;

    public MyIconButton(ImageIcon iconNormal, ImageIcon iconEnable, ImageIcon iconDisable, String tip) {
        super(iconNormal);

        this.iconEnable = iconEnable;
        this.iconDisable = iconDisable;
        this.tip = tip;
    }

    /**
     * 初始化，设置按钮属性：无边，无焦点渲染，无内容区，各边距0
     */
    private void initialize() {
        this.setBorderPainted(false);
        this.setFocusPainted(false);
        this.setContentAreaFilled(false);
        this.setFocusable(true);
        this.setMargin(new Insets(0, 0, 0, 0));
    }

    /**
     * 设置按钮图标：鼠标移过、按压、失效的图标和设置按钮提醒
     */
    private void setUp() {
        this.setRolloverIcon(iconEnable);
        this.setPressedIcon(iconEnable);
        this.setDisabledIcon(iconDisable);

        if (!tip.equals("")) {
            this.setToolTipText(tip);
        }
    }
}
