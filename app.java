import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Random;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import it.unisa.dia.gas.jpbc.*;

public class app {
    private static String[] messages;
    private static Element[] signs;
    private static String[] ids;

    public static void main(String[] args) {
        JFrame frmMain = new JFrame("BLS");
        frmMain.setSize(400, 300);
        frmMain.setLocation(200, 200);
        frmMain.setLayout(null);

        JPanel p1 = new JPanel();

        p1.setBounds(50, 50, 300, 60);
        p1.setBackground(Color.GREEN);
        p1.setLayout(new FlowLayout());

        JButton b1 = new JButton("签名发送");
        JButton b2 = new JButton("篡改");
        JButton b3 = new JButton("添加");
        JLabel Mcount = new JLabel("消息个数:");
        JTextField countField = new JTextField();
        JLabel Rtext = new JLabel("消息:");
        JTextArea textArea = new JTextArea();
        JLabel Stext = new JLabel("签名结果:");
        JTextArea resultArea = new JTextArea();
        countField.setPreferredSize(new Dimension(50, 30));
        Rtext.setPreferredSize(new Dimension(50, 30));
        textArea.setPreferredSize(new Dimension(250, 150));
        Stext.setPreferredSize(new Dimension(80, 30));
        resultArea.setPreferredSize(new Dimension(100, 30));
        // 输入消息
        b3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 消息个数
                Integer num = Integer.parseInt(countField.getText());
                messages = new String[num];
                for (int i = 0; i < num; i++) {
                    messages[i] = JOptionPane.showInputDialog("输入消息 " + (i + 1) + ":");
                }
                showNum(messages);
                // for (String string : messages) {
                // textArea.append("消息:" + string+"\n");
                // }
                for (int i = 0; i < messages.length; i++) {
                    textArea.append("消息:" + i + messages[i] + "\n");
                }
            }
        });
        // 签名消息
        b1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String r = sign(messages);
                    resultArea.append(r);
                } catch (Exception ex) {
                }
            }
        });
        b2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modify(messages);
            }
        });
        p1.add(Mcount);
        p1.add(countField);
        p1.add(b3);
        p1.add(b1);
        p1.add(b2);
        p1.add(Rtext);
        p1.add(textArea);
        p1.add(Stext);
        p1.add(resultArea);

        JPanel p2 = new JPanel();
        JButton b4 = new JButton("验证");
        JLabel verifyLabel = new JLabel("验证结果：");
        JTextArea verifyArea = new JTextArea();
        JLabel findLabel = new JLabel("无效签名：");
        JTextArea findArea = new JTextArea();
        findLabel.setPreferredSize(new Dimension(80, 50));
        verifyLabel.setPreferredSize(new Dimension(80, 30));
        verifyArea.setPreferredSize(new Dimension(80, 20));
        findArea.setPreferredSize(new Dimension(200, 150));
        // JButton b5 = new JButton("按钮5");
        // JButton b6 = new JButton("按钮6");

        p2.add(b4);
        p2.add(verifyLabel);
        p2.add(verifyArea);
        p2.add(findLabel);
        p2.add(findArea);
        b4.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String r = verify(messages);
                    verifyArea.append(r);
                    String res = Invalid(messages);
                    findArea.append(res);
                } catch (Exception ex) {
                }
            }
        });
        // p2.add(b5);
        // p2.add(b6);

        p2.setBackground(Color.GREEN);
        p2.setBounds(10, 150, 300, 60);

        JTabbedPane tp = new JTabbedPane();
        tp.add(p1);
        tp.add(p2);

        // 设置tab的标题
        tp.setTitleAt(0, "A");
        tp.setTitleAt(1, "B");

        frmMain.setContentPane(tp);
        frmMain.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frmMain.setVisible(true);
    }

    // 测试函数
    private static void showNum(String[] args) {
        for (String string : args) {
            System.out.println(string);
        }
    }

    // 调用bls的as函数聚合签名
    private static String sign(String[] args) throws Exception {
        signs = BLS.SwingSign(args);
        if (signs.length != 0) {
            return "聚合签名成功";
        } else {
            return "聚合签名失败";
        }
        // if (r) {
        // return "聚合签名成功";
        // } else {
        // return "聚合签名失败";
        // }
        // return "聚合签名成功";
    }

    private static void getIds() {
        ids = BLS.getIds(messages);
    }

    // 调用bls的ve函数验证
    private static String verify(String[] args) throws Exception {
        // String r = bls.ve(args);
        getIds();
        boolean res = BLS.SwingVerify(signs, args, ids);
        if (res) {
            return "验证成功";
        } else {
            return "验证失败";
        }
    }

    // 篡改消息，模拟发送时消息出错。
    private static void modify(String[] args) {
        // Integer len = args.length;
        // Random r = new Random();
        // Integer pos1 = r.nextInt(len - 1);
        // Integer pos2 = r.nextInt(len - 1);
        // Integer pos3 = r.nextInt(len - 1);
        // args[pos1] = "a";
        // args[pos2] = "b";
        // args[pos3] = "c";
        Integer len = args.length;
        Random r = new Random();
        Integer pos1 = r.nextInt(len - 1);
        args[pos1] = "this is a message has been modified.";
    }

    // 找出无效签名
    private static String Invalid(String[] args) throws Exception {
        ArrayList<Integer> res = BLS.SwingGetInvalid(args, ids);
        System.out.println(res);
        String str = "";
        for (Integer integer : res) {
            str = str + "第" + integer + "个消息签名错误，消息值：" + args[integer] + "\n";
        }
        return str;
    }
}