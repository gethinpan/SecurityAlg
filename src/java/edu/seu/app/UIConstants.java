package edu.seu.app;

import javax.swing.*;
import java.awt.*;

public class UIConstants {
    /**
     * AppMainWindow大小
     */
    public static final int MAIN_WINDOW_X = 240;
    public static final int MAIN_WINDOW_Y = 100;
    public static final int MAIN_WINDOW_WIDTH = 885;
    public static final int MAIN_WINDOW_HEIGHT = 636;

    public static final String MAIN_WINDOW_TITLE = "现代密码学仿真器";

    // 主窗口背景色
    public static final Color MAIN_WINDOW_BACK_COLOR = Color.WHITE;

    // 工具栏背景色
    public static final Color TOOL_BAR_BACK_COLOR = new Color(37, 174, 96);

    /**
     * 字体
     */
    // 标题字体
    public static final Font FONT_TITLE = new Font("微软雅黑", 0, 27);
    // 普通字体
    public final static Font FONT_NORMAL = new Font("微软雅黑", 0, 13);
    // radio字体
    public final static Font FONT_RADIO = new Font("微软雅黑", 0, 20);

    /**
     * 工具栏图标
     */
    public static final ImageIcon ICON_KEY_PARAMETER = new ImageIcon(AppMainWindow.class.getResource("/icon/key.png"));
    public static final ImageIcon ICON_SEND = new ImageIcon(AppMainWindow.class.getResource("/icon/send.png"));
    public static final ImageIcon ICON_RECEIVE = new ImageIcon(AppMainWindow.class.getResource("/icon/receive.png"));

    public static final ImageIcon ICON_SAVE = new ImageIcon(AppMainWindow.class.getResource("/icon/saveButton.png"));

    /**
     * 样式布局相关
     */
    // 主面板水平间隔
    public final static int MAIN_H_GAP = 25;
    // 主面板Label 大小
    public final static Dimension LABLE_SIZE = new Dimension(1300, 30);
    // Item Label 大小
    public final static Dimension LABLE_SIZE_ITEM = new Dimension(78, 30);
    // Item text field 大小
    public final static Dimension TEXT_FIELD_SIZE_ITEM = new Dimension(400, 24);
    // radio 大小
    public final static Dimension RADIO_SIZE = new Dimension(1300, 60);
    // 高级选项面板Item 大小
    public final static Dimension PANEL_ITEM_SIZE = new Dimension(1300, 40);
}
