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
        panelParameter.setBounds(25, 20, 800, 600);
        panelParameter.setLayout(null);

        // 对称加密算法选择
        JLabel symEncLabel = new JLabel("对称加密算法：");
        symEncLabel.setFont(UIConstants.FONT_RADIO);
        symEncLabel.setBounds(25, 20, 150, 25);

        JRadioButton desButton = new JRadioButton("DES", true);
        desButton.setFont(UIConstants.FONT_RADIO);
        desButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        desButton.setMinimumSize(UIConstants.RADIO_SIZE);
        desButton.setBounds(200, 20, 80, 25);

        JRadioButton aesButton = new JRadioButton("AES", false);
        aesButton.setFont(UIConstants.FONT_RADIO);
        aesButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        aesButton.setMinimumSize(UIConstants.RADIO_SIZE);
        aesButton.setBounds(300, 20, 80, 25);

        // 对称密钥生成方案
        JLabel symKeyLabel = new JLabel("对称密钥生成：");
        symKeyLabel.setFont(UIConstants.FONT_RADIO);
        symKeyLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeyLabel.setBounds(25, 60, 150, 25);

        JComboBox<String> symKeyBox = new JComboBox<>();
        symKeyBox.addItem("种子生成");
        symKeyBox.addItem("随机生成");
        symKeyBox.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeyBox.setFont(UIConstants.FONT_RADIO);
        symKeyBox.setBounds(200, 60, 120, 27);

        JLabel symKeySeedLabel = new JLabel("请输入种子");
        symKeySeedLabel.setFont(UIConstants.FONT_RADIO);
        symKeySeedLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeySeedLabel.setBounds(350, 60, 120, 25);

        JTextField symKeySeedField = new JTextField();
        symKeySeedField.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeySeedField.setFont(UIConstants.FONT_RADIO);
        symKeySeedField.setBounds(450, 60, 120, 27);
        symKeySeedField.setEnabled(true);

        JLabel hashLabel = new JLabel("Hash函数：");
        hashLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        hashLabel.setFont(UIConstants.FONT_RADIO);
        hashLabel.setBounds(25, 100, 150, 25);

        JRadioButton md5Button = new JRadioButton("MD5", true);
        md5Button.setFont(UIConstants.FONT_RADIO);
        md5Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        md5Button.setMinimumSize(UIConstants.RADIO_SIZE);
        md5Button.setBounds(200, 100, 120, 25);

        JRadioButton sha224Button = new JRadioButton("SHA224", false);
        sha224Button.setFont(UIConstants.FONT_RADIO);
        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha224Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha224Button.setBounds(350, 100, 120, 25);

        JRadioButton sha256Button = new JRadioButton("SHA256", false);
        sha256Button.setFont(UIConstants.FONT_RADIO);
        sha256Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha256Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha256Button.setBounds(500, 100, 120, 25);

        JRadioButton sha384Button = new JRadioButton("SHA384", false);
        sha384Button.setFont(UIConstants.FONT_RADIO);
        sha384Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha384Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha384Button.setBounds(200, 130, 120, 25);

        JRadioButton sha512Button = new JRadioButton("SHA512", false);
        sha512Button.setFont(UIConstants.FONT_RADIO);
        sha512Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha512Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha512Button.setBounds(350, 130, 120, 25);

        JLabel rsaModule1Label = new JLabel("发送方公钥模数长度：");
        rsaModule1Label.setFont(UIConstants.FONT_RADIO);
        rsaModule1Label.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule1Label.setBounds(25, 170, 200, 25);

        JTextField rsaModule1Field = new JTextField();
        rsaModule1Field.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule1Field.setFont(UIConstants.FONT_RADIO);
        rsaModule1Field.setBounds(250, 170, 120, 27);
        rsaModule1Field.setEnabled(true);

        JLabel rsaModule2Label = new JLabel("接收方公钥模数长度：");
        rsaModule2Label.setFont(UIConstants.FONT_RADIO);
        rsaModule2Label.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule2Label.setBounds(25, 210, 200, 25);

        JTextField rsaModule2Field = new JTextField();
        rsaModule2Field.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule2Field.setFont(UIConstants.FONT_RADIO);
        rsaModule2Field.setBounds(250, 210, 120, 27);
        rsaModule2Field.setEnabled(true);

        panelParameter.add(symEncLabel);
        panelParameter.add(desButton);
        panelParameter.add(aesButton);
        panelParameter.add(symKeyLabel);
        panelParameter.add(symKeyBox);
        panelParameter.add(symKeySeedLabel);
        panelParameter.add(symKeySeedField);
        panelParameter.add(hashLabel);
        panelParameter.add(md5Button);
        panelParameter.add(sha224Button);
        panelParameter.add(sha256Button);
        panelParameter.add(sha384Button);
        panelParameter.add(sha512Button);
        panelParameter.add(rsaModule1Label);
        panelParameter.add(rsaModule1Field);
        panelParameter.add(rsaModule2Label);
        panelParameter.add(rsaModule2Field);


//        // 对称加密算法选择面板
//        JPanel symEncPanel = new JPanel();
//        symEncPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        symEncPanel.setLayout(new GridLayout(1, 3));
//        JLabel symEncLabel = new JLabel("对称加密算法");
//        symEncLabel.setFont(UIConstants.FONT_RADIO);
//
//        JRadioButton desButton = new JRadioButton("DES");
//        desButton.setFont(UIConstants.FONT_RADIO);
//        desButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        desButton.setSize(UIConstants.RADIO_SIZE);
//
//        JRadioButton aesButton = new JRadioButton("AES");
//        aesButton.setFont(UIConstants.FONT_RADIO);
//        aesButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        aesButton.setSize(UIConstants.RADIO_SIZE);
//
//        symEncPanel.add(symEncLabel);
//        symEncPanel.add(desButton);
//        symEncPanel.add(aesButton);
//
//        // 对称密钥方案
//        JPanel symKeyPanel = new JPanel();
//        symKeyPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        symKeyPanel.setLayout(new GridLayout(1, 3));
//        JLabel symKeyLabel = new JLabel("对称密钥方案");
//        symKeyLabel.setFont(UIConstants.FONT_RADIO);
//
//        JComboBox<String> symKeys = new JComboBox<>();
//        symKeys.addItem("种子生成");
//        symKeys.addItem("随机生成");
//        symKeys.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        symKeys.setSize(UIConstants.RADIO_SIZE);
//        symKeys.setFont(UIConstants.FONT_RADIO);
//
//        JTextField keySeed = new JTextField();
//        keySeed.setFont(UIConstants.FONT_RADIO);
//        keySeed.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        Dimension preferredSize = new Dimension(130, 26);
//        keySeed.setPreferredSize(preferredSize);
//
//        symKeyPanel.add(symKeyLabel);
//        symKeyPanel.add(symKeys);
//        symKeyPanel.add(keySeed);
//
//        // Hash函数
//        JPanel hashPanel = new JPanel();
//        hashPanel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        hashPanel.setLayout(new GridLayout(2, 3));
//        JLabel hashLabel = new JLabel("HASH函数");
//        hashLabel.setFont(UIConstants.FONT_RADIO);
//
//        JRadioButton md5Button = new JRadioButton("MD5");
//        md5Button.setFont(UIConstants.FONT_RADIO);
//        md5Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        md5Button.setSize(UIConstants.RADIO_SIZE);
//
//        JRadioButton sha224Button = new JRadioButton("SHA224");
//        sha224Button.setFont(UIConstants.FONT_RADIO);
//        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        sha224Button.setSize(UIConstants.RADIO_SIZE);
//
//        JRadioButton sha256Button = new JRadioButton("SHA256");
//        sha224Button.setFont(UIConstants.FONT_RADIO);
//        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        sha224Button.setSize(UIConstants.RADIO_SIZE);
//
//        JRadioButton sha384Button = new JRadioButton("SHA384");
//        sha224Button.setFont(UIConstants.FONT_RADIO);
//        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        sha224Button.setSize(UIConstants.RADIO_SIZE);
//
//        JRadioButton sha512Button = new JRadioButton("SHA512");
//        sha224Button.setFont(UIConstants.FONT_RADIO);
//        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
//        sha224Button.setSize(UIConstants.RADIO_SIZE);
//
//        hashPanel.add(hashLabel);
//        hashPanel.add(md5Button);
//        hashPanel.add(sha224Button);
//        hashPanel.add(sha256Button);
//        hashPanel.add(sha384Button);
//        hashPanel.add(sha512Button);
//
//        panelParameter.add(symEncPanel);
//        panelParameter.add(symKeyPanel);
//        panelParameter.add(hashPanel);

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
