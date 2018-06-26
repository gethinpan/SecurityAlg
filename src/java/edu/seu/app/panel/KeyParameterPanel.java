package edu.seu.app.panel;

import edu.seu.app.MyIconButton;
import edu.seu.app.UIConstants;

import javax.swing.*;
import java.awt.*;

public class KeyParameterPanel extends JPanel {
    private static MyIconButton buttonSave;

    public KeyParameterPanel() {
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

        JLabel labelTitle = new JLabel("加密参数设定");
        labelTitle.setFont(UIConstants.FONT_TITLE);
        labelTitle.setForeground(UIConstants.TOOL_BAR_BACK_COLOR);
        panelUp.add(labelTitle);

        return panelUp;
    }

    /**
     * 中部面板
     */
    private JPanel getCenterPanel() {
        JPanel centerPanel = new JPanel();
        centerPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        centerPanel.setLayout(new GridLayout(1, 1));

        JPanel panelParameter = new JPanel();
        panelParameter.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelParameter.setLayout(new FlowLayout(FlowLayout.LEFT, UIConstants.MAIN_H_GAP, 0));

        // 对称加密算法选择面板
        JPanel symEncPanel = new JPanel();
        symEncPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symEncPanel.setLayout(new GridLayout(1, 3));
        JLabel symEncLabel = new JLabel("对称加密算法");
        symEncLabel.setFont(UIConstants.FONT_RADIO);

        JRadioButton desButton = new JRadioButton("DES");
        desButton.setFont(UIConstants.FONT_RADIO);
        desButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        desButton.setSize(UIConstants.RADIO_SIZE);

        JRadioButton aesButton = new JRadioButton("AES");
        aesButton.setFont(UIConstants.FONT_RADIO);
        aesButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        aesButton.setSize(UIConstants.RADIO_SIZE);

        symEncPanel.add(symEncLabel);
        symEncPanel.add(desButton);
        symEncPanel.add(aesButton);

        // 对称密钥方案
        JPanel symKeyPanel = new JPanel();
        symKeyPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeyPanel.setLayout(new GridLayout(1, 3));
        JLabel symKeyLabel = new JLabel("对称密钥方案");
        symKeyLabel.setFont(UIConstants.FONT_RADIO);

        JComboBox<String> symKeys = new JComboBox<>();
        symKeys.addItem("种子生成");
        symKeys.addItem("随机生成");
        symKeys.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeys.setSize(UIConstants.RADIO_SIZE);
        symKeys.setFont(UIConstants.FONT_RADIO);

        JTextField keySeed = new JTextField();
        keySeed.setFont(UIConstants.FONT_RADIO);
        keySeed.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        Dimension preferredSize = new Dimension(130, 26);
        keySeed.setPreferredSize(preferredSize);

        symKeyPanel.add(symKeyLabel);
        symKeyPanel.add(symKeys);
        symKeyPanel.add(keySeed);

        // Hash函数
        JPanel hashPanel = new JPanel();
        hashPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        hashPanel.setLayout(new GridLayout(2, 3));
        JLabel hashLabel = new JLabel("HASH函数");
        hashLabel.setFont(UIConstants.FONT_RADIO);

        JRadioButton md5Button = new JRadioButton("MD5");
        md5Button.setFont(UIConstants.FONT_RADIO);
        md5Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        md5Button.setSize(UIConstants.RADIO_SIZE);

        JRadioButton sha224Button = new JRadioButton("SHA224");
        sha224Button.setFont(UIConstants.FONT_RADIO);
        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha224Button.setSize(UIConstants.RADIO_SIZE);

        JRadioButton sha256Button = new JRadioButton("SHA256");
        sha224Button.setFont(UIConstants.FONT_RADIO);
        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha224Button.setSize(UIConstants.RADIO_SIZE);

        JRadioButton sha384Button = new JRadioButton("SHA384");
        sha224Button.setFont(UIConstants.FONT_RADIO);
        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha224Button.setSize(UIConstants.RADIO_SIZE);

        JRadioButton sha512Button = new JRadioButton("SHA512");
        sha224Button.setFont(UIConstants.FONT_RADIO);
        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha224Button.setSize(UIConstants.RADIO_SIZE);

        hashPanel.add(hashLabel);
        hashPanel.add(md5Button);
        hashPanel.add(sha224Button);
        hashPanel.add(sha256Button);
        hashPanel.add(sha384Button);
        hashPanel.add(sha512Button);

        panelParameter.add(symEncPanel);
        panelParameter.add(symKeyPanel);
        panelParameter.add(hashPanel);

        centerPanel.add(panelParameter);

        return centerPanel;
    }

    /**
     * 底部面板
     */
    private JPanel getDownPanel() {
        JPanel panelDown = new JPanel();
        panelDown.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        panelDown.setLayout(new FlowLayout(FlowLayout.RIGHT, UIConstants.MAIN_H_GAP, 15));

        buttonSave = new MyIconButton(UIConstants.ICON_SAVE, UIConstants.ICON_SAVE,
                UIConstants.ICON_SAVE, "");
        panelDown.add(buttonSave);

        return panelDown;
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame();
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.setBounds(UIConstants.MAIN_WINDOW_X, UIConstants.MAIN_WINDOW_Y,
                        UIConstants.MAIN_WINDOW_WIDTH, UIConstants.MAIN_WINDOW_HEIGHT);
                frame.add(new KeyParameterPanel());
                frame.setVisible(true);
            }
        });
    }
}
