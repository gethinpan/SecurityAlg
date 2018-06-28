package edu.seu.app;

import edu.seu.app.panel.*;

import javax.swing.*;
import java.awt.*;

public class AppMainWindow {
    private JFrame frame;

    private static JPanel mainPanel;
    public static JPanel mainPanelCenter;

    public static KeyParameterPanel keyParameterPanel;
    public static SendPanel sendPanel;
    public static ReceivePanel receivePanel;
    public static SettingPanel settingPanel;

    public static SecurityUtil securityUtil;

    public AppMainWindow() {
        initialize();
    }

    private void initialize() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
                | UnsupportedLookAndFeelException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        frame = new JFrame();
        frame.setBounds(UIConstants.MAIN_WINDOW_X, UIConstants.MAIN_WINDOW_Y,
                UIConstants.MAIN_WINDOW_WIDTH, UIConstants.MAIN_WINDOW_HEIGHT);
        frame.setTitle(UIConstants.MAIN_WINDOW_TITLE);
        frame.setIconImage(UIConstants.ICON_IMAGE);
        frame.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);

        mainPanel = new JPanel(true);
        mainPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        mainPanel.setLayout(new BorderLayout());

        ToolBarPanel toolbar = new ToolBarPanel();
        keyParameterPanel = new KeyParameterPanel();
        sendPanel = new SendPanel();
        receivePanel = new ReceivePanel();
        settingPanel = new SettingPanel();

        mainPanel.add(toolbar, BorderLayout.WEST);

        mainPanelCenter = new JPanel(true);
        mainPanelCenter.setLayout(new BorderLayout());
        mainPanelCenter.add(keyParameterPanel, BorderLayout.CENTER);


        mainPanel.add(mainPanelCenter, BorderLayout.CENTER);

        frame.add(mainPanel);
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    AppMainWindow window = new AppMainWindow();
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}