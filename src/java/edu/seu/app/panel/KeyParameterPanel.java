package edu.seu.app.panel;

import edu.seu.app.AppMainWindow;
import edu.seu.app.MyIconButton;
import edu.seu.app.SecurityUtil;
import edu.seu.app.UIConstants;
import edu.seu.security.RSAKey;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

import static edu.seu.app.AppMainWindow.securityUtil;

public class KeyParameterPanel extends JPanel {
    private static MyIconButton buttonSave;
    private static JRadioButton desButton;
    private static JRadioButton aesButton;
    private static JComboBox<String> symKeyBox;
    private static JTextField symKeySeedField;
    private static JRadioButton md5Button;
    private static JRadioButton sha224Button;
    private static JRadioButton sha256Button;
    private static JRadioButton sha384Button;
    private static JRadioButton sha512Button;
    private static JTextField rsaModule1Field;
    private static JTextField rsaModule2Field;
    private static JTextArea user1Parameter;
    private static JTextArea user2Parameter;

    private static String symEncAlg;
    private static String symKeySeed;
    private static String hashAlg;
    private static String rsaKeySize1;
    private static String rsaKeySize2;

    static {
        symEncAlg = "DES";
        symKeySeed = null;
        hashAlg = "MD5";
        rsaKeySize1 = "2048";
        rsaKeySize2 = "2048";
    }

    public KeyParameterPanel() {
        initialize();
        addComponent();
        addListener();
    }

    private void initialize() {
        this.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        this.setLayout(new BorderLayout());
        AppMainWindow.securityUtil = new SecurityUtil(symEncAlg,
                symKeySeed, hashAlg, rsaKeySize1, rsaKeySize2);
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

        desButton = new JRadioButton("DES", true);
        desButton.setFont(UIConstants.FONT_RADIO);
        desButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        desButton.setMinimumSize(UIConstants.RADIO_SIZE);
        desButton.setBounds(250, 20, 80, 25);

        aesButton = new JRadioButton("AES", false);
        aesButton.setFont(UIConstants.FONT_RADIO);
        aesButton.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        aesButton.setMinimumSize(UIConstants.RADIO_SIZE);
        aesButton.setBounds(400, 20, 80, 25);

        ButtonGroup symEncButtons = new ButtonGroup();
        symEncButtons.add(desButton);
        symEncButtons.add(aesButton);

        // 对称密钥生成方案
        JLabel symKeyLabel = new JLabel("对称密钥生成：");
        symKeyLabel.setFont(UIConstants.FONT_RADIO);
        symKeyLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeyLabel.setBounds(25, 60, 150, 25);

        symKeyBox = new JComboBox<>();
        symKeyBox.addItem("随机生成");
        symKeyBox.addItem("种子生成");

        symKeyBox.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeyBox.setFont(UIConstants.FONT_RADIO);
        symKeyBox.setBounds(250, 60, 120, 27);
        symKeyBox.setSelectedIndex(0);

        JLabel symKeySeedLabel = new JLabel("请输入种子：");
        symKeySeedLabel.setFont(UIConstants.FONT_RADIO);
        symKeySeedLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeySeedLabel.setBounds(400, 60, 120, 25);

        symKeySeedField = new JTextField();
        symKeySeedField.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        symKeySeedField.setFont(UIConstants.FONT_RADIO);
        symKeySeedField.setBounds(535, 60, 120, 27);
        symKeySeedField.setEnabled(false);

        JLabel hashLabel = new JLabel("Hash函数：");
        hashLabel.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        hashLabel.setFont(UIConstants.FONT_RADIO);
        hashLabel.setBounds(25, 100, 150, 25);

        md5Button = new JRadioButton("MD5", true);
        md5Button.setFont(UIConstants.FONT_RADIO);
        md5Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        md5Button.setMinimumSize(UIConstants.RADIO_SIZE);
        md5Button.setBounds(250, 100, 120, 25);

        sha224Button = new JRadioButton("SHA224", false);
        sha224Button.setFont(UIConstants.FONT_RADIO);
        sha224Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha224Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha224Button.setBounds(400, 100, 120, 25);

        sha256Button = new JRadioButton("SHA256", false);
        sha256Button.setFont(UIConstants.FONT_RADIO);
        sha256Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha256Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha256Button.setBounds(535, 100, 120, 25);

        sha384Button = new JRadioButton("SHA384", false);
        sha384Button.setFont(UIConstants.FONT_RADIO);
        sha384Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha384Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha384Button.setBounds(250, 130, 120, 25);

        sha512Button = new JRadioButton("SHA512", false);
        sha512Button.setFont(UIConstants.FONT_RADIO);
        sha512Button.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        sha512Button.setMinimumSize(UIConstants.RADIO_SIZE);
        sha512Button.setBounds(400, 130, 120, 25);

        ButtonGroup hashButtons = new ButtonGroup();
        hashButtons.add(md5Button);
        hashButtons.add(sha224Button);
        hashButtons.add(sha256Button);
        hashButtons.add(sha384Button);
        hashButtons.add(sha512Button);

        JLabel rsaModule1Label = new JLabel("发送方公钥模数长度：");
        rsaModule1Label.setFont(UIConstants.FONT_RADIO);
        rsaModule1Label.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule1Label.setBounds(25, 170, 200, 25);

        rsaModule1Field = new JTextField();
        rsaModule1Field.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule1Field.setFont(UIConstants.FONT_RADIO);
        rsaModule1Field.setBounds(250, 170, 120, 27);
        rsaModule1Field.setEnabled(true);

        JLabel rsaModule2Label = new JLabel("接收方公钥模数长度：");
        rsaModule2Label.setFont(UIConstants.FONT_RADIO);
        rsaModule2Label.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule2Label.setBounds(25, 210, 200, 25);

        rsaModule2Field = new JTextField();
        rsaModule2Field.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        rsaModule2Field.setFont(UIConstants.FONT_RADIO);
        rsaModule2Field.setBounds(250, 210, 120, 27);
        rsaModule2Field.setEnabled(true);

        user1Parameter = new JTextArea();
        user1Parameter.setFont(UIConstants.FONT_NORMAL);
        user1Parameter.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        user1Parameter.setBounds(25, 250, 375, 230);
        user1Parameter.setEnabled(false);
        user1Parameter.setLineWrap(true);
        Border border1 = BorderFactory.createEtchedBorder();
        user1Parameter.setBorder(border1);
        user1Parameter.setText("用户A默认参数如下：\n");
        user1Parameter.append(AppMainWindow.securityUtil.getParameterInfo(1));
        JScrollPane scroll1 = new JScrollPane();
        scroll1.setBounds(25, 250, 375, 230);
        scroll1.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll1.setViewportView(user1Parameter);

        user2Parameter = new JTextArea();
        user2Parameter.setFont(UIConstants.FONT_NORMAL);
        user2Parameter.setBackground(UIConstants.MAIN_WINDOW_BACK_COLOR);
        user2Parameter.setBounds(420, 250, 375, 230);
        user2Parameter.setEnabled(false);
        user2Parameter.setLineWrap(true);
        Border border2 = BorderFactory.createEtchedBorder();
        user2Parameter.setBorder(border2);
        user2Parameter.setText("用户B默认参数如下：\n");
        user2Parameter.append(AppMainWindow.securityUtil.getParameterInfo(2));
        JScrollPane scroll2 = new JScrollPane();
        scroll2.setBounds(420, 250, 375, 230);
        scroll2.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll2.setViewportView(user2Parameter);

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
        panelParameter.add(scroll1);
        panelParameter.add(scroll2);

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

        buttonSave = new MyIconButton(UIConstants.ICON_SAVE_BUTTON, UIConstants.ICON_SAVE_BUTTON_ENABLE,
                UIConstants.ICON_SAVE_BUTTON_DISABLE, "");
        panelDown.add(buttonSave);

        return panelDown;
    }

    /**
     * 为各组件添加事件监听
     */
    private void addListener() {
        desButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                symEncAlg = "DES";
            }
        });

        aesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                symEncAlg = "AES";
            }
        });

        symKeyBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (symKeyBox.getSelectedIndex() == 0) {
                    symKeySeedField.setEnabled(false);
                } else {
                    symKeySeedField.setEnabled(true);
                }
            }
        });

        md5Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "MD5";
            }
        });

        sha224Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA224";
            }
        });

        sha256Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA256";
            }
        });

        sha384Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA384";
            }
        });

        sha512Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA512";
            }
        });

        buttonSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (symKeyBox.getSelectedIndex() == 0) {
                    symKeySeed = null;
                } else {
                    symKeySeed = symKeySeedField.getText().trim();
                    if (symKeySeed.equals("")) {
                        JOptionPane.showMessageDialog(getParent(),"对称密钥种子不能为空！","提示",JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }
                }

                rsaKeySize1 = rsaModule1Field.getText().trim();
                rsaKeySize2 = rsaModule2Field.getText().trim();

                if (rsaKeySize1.equals("") || (Integer.parseInt(rsaKeySize1) < 1024)) {
                    JOptionPane.showMessageDialog(getParent(),"发送方公钥模数长度不符合要求（1024-2048）！","提示",JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                if (rsaKeySize2.equals("") || (Integer.parseInt(rsaKeySize2) < 1024)) {
                    JOptionPane.showMessageDialog(getParent(),"接收方公钥模数长度不符合要求（1024-2048）！","提示",JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                securityUtil = new SecurityUtil(symEncAlg, symKeySeed, hashAlg, rsaKeySize1, rsaKeySize2);

                user1Parameter.setText("用户A参数如下：\n");
                user1Parameter.append(securityUtil.getParameterInfo(1));

                user2Parameter.setText("用户B参数如下：\n");
                user2Parameter.append(securityUtil.getParameterInfo(2));
                JOptionPane.showMessageDialog(getParent(),"加密参数设置成功！","提示",JOptionPane.INFORMATION_MESSAGE);
            }
        });
    }

    /**
     * byte array 转 16进制字符串
     * @param bytes
     */
    private String byteArray2hexStr(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b & 0xff));
        }
        return hex.toString();
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
