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

    public static final String MAIN_WINDOW_TITLE = "Data Enc";
    public static final String VERSION = "v1.0";
    public static final Image ICON_IMAGE = Toolkit.getDefaultToolkit()
            .getImage(AppMainWindow.class.getResource("/icon/dataEnc.png"));

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
    public static final ImageIcon ICON_KEY_PARAMETER_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/keyEnable.png"));
    public static final ImageIcon ICON_SEND = new ImageIcon(AppMainWindow.class.getResource("/icon/send.png"));
    public static final ImageIcon ICON_SEND_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/sendEnable.png"));
    public static final ImageIcon ICON_RECEIVE = new ImageIcon(AppMainWindow.class.getResource("/icon/receive.png"));
    public static final ImageIcon ICON_RECEIVE_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/receiveEnable.png"));
    public static final ImageIcon ICON_SETTING = new ImageIcon(AppMainWindow.class.getResource("/icon/setting.png"));
    public static final ImageIcon ICON_SETTING_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/settingEnable.png"));

    public static final ImageIcon ICON_DATA_ENC = new ImageIcon(AppMainWindow.class.getResource("/icon/dataEnc.png"));

    public static final ImageIcon ICON_SAVE_BUTTON = new ImageIcon(AppMainWindow.class.getResource("/icon/saveButton.png"));
    public static final ImageIcon ICON_SAVE_BUTTON_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/saveButtonEnable.png"));
    public static final ImageIcon ICON_SAVE_BUTTON_DISABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/saveButtonDisable.png"));

    public static final ImageIcon ICON_SEND_BUTTON = new ImageIcon(AppMainWindow.class.getResource("/icon/sendButton.png"));
    public static final ImageIcon ICON_SEND_BUTTON_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/sendButtonEnable.png"));
    public static final ImageIcon ICON_SEND_BUTTON_DISABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/sendButtonDisable.png"));

    public static final ImageIcon ICON_DECRYPT_BUTTON = new ImageIcon(AppMainWindow.class.getResource("/icon/decryptButton.png"));
    public static final ImageIcon ICON_DECRYPT_BUTTON_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/decryptButtonEnable.png"));
    public static final ImageIcon ICON_DECRYPT_BUTTON_DISABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/decryptButtonDisable.png"));

    public static final ImageIcon ICON_AUTH_BUTTON = new ImageIcon(AppMainWindow.class.getResource("/icon/authButton.png"));
    public static final ImageIcon ICON_AUTH_BUTTON_ENABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/authButtonEnable.png"));
    public static final ImageIcon ICON_AUTH_BUTTON_DISABLE = new ImageIcon(AppMainWindow.class.getResource("/icon/authButtonDisable.png"));

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
