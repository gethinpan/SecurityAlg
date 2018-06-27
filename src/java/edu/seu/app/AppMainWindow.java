package edu.seu.app;

import edu.seu.app.panel.KeyParameterPanel;
import edu.seu.app.panel.ReceivePanel;
import edu.seu.app.panel.SendPanel;
import edu.seu.app.panel.ToolBarPanel;

import javax.swing.*;
import java.awt.*;

public class AppMainWindow {
    private JFrame frame;

    private static JPanel mainPanel;
    public static JPanel mainPanelCenter;

    public static KeyParameterPanel keyParameterPanel;
    public static SendPanel sendPanel;
    public static ReceivePanel receivePanel;

    public static SecurityUtil securityUtil;

    public AppMainWindow() {
        initialize();
    }

    private void initialize() {
        frame = new JFrame();
        frame.setBounds(UIConstants.MAIN_WINDOW_X, UIConstants.MAIN_WINDOW_Y,
                UIConstants.MAIN_WINDOW_WIDTH, UIConstants.MAIN_WINDOW_HEIGHT);
        frame.setTitle(UIConstants.MAIN_WINDOW_TITLE);
        frame.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);

        mainPanel = new JPanel(true);
        mainPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        mainPanel.setLayout(new BorderLayout());

        ToolBarPanel toolbar = new ToolBarPanel();
        keyParameterPanel = new KeyParameterPanel();
        sendPanel = new SendPanel();
        receivePanel = new ReceivePanel();

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