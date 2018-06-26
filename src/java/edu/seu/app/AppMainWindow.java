package edu.seu.app;

import javax.swing.*;
import java.awt.*;

public class AppMainWindow {
    private JFrame frame;

    public AppMainWindow() {
        initialize();
    }

    private void initialize() {
        frame = new JFrame();
        frame.setBounds(UIConstants.MAIN_WINDOW_X, UIConstants.MAIN_WINDOW_Y,
                UIConstants.MAIN_WINDOW_WIDTH, UIConstants.MAIN_WINDOW_HEIGHT);
        frame.setTitle(UIConstants.MAIN_WINDOW_TITLE);
        frame.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
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