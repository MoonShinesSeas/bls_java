import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;

public class BLS {
    private static List<Element[]> mysigmaList;

    /*
     * FileName:椭圆曲线参数
     * pubFileName:公钥参数
     * KGC_SK_FileName:私钥保存文件
     */
    public static void KeyGen(String FileName, String pubFileName, String KGC_SK_FileName) {
        Pairing bp = PairingFactory.getPairing(FileName);
        // G1的生成元P
        Element P = bp.getG1().newRandomElement().getImmutable();
        // 计算主私钥和公钥
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element P_Pub = P.mulZn(s);

        Properties pubParamProp = new Properties();

        // 后面对写的元素统一采用如下方法：首先将元素转为字节数组，然后进行Base64编码为可读字符串
        pubParamProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubParamProp.setProperty("P_Pub", Base64.getEncoder().encodeToString(P_Pub.toBytes()));

        storePropToFile(pubParamProp, pubFileName);

        Properties param_s = new Properties();// 私钥不存入公开参数中,由KGC自己保存
        param_s.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(param_s, KGC_SK_FileName);
    }

    // 根据用户id生成私钥
    public static void PartialPrivateKeyGen(String pairingParametersFileName, String id, String KGC_SK_FileName)
            throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        // 使用HASH 将 id 转为QID
        byte[] idHash = HASH(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        // 从文件中读取 主私钥
        Properties mskProp = loadPropFromFile(KGC_SK_FileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable(); // Base64编码后对应的恢复元素的方法

        // 计算用户私钥, 这里应该将私钥安全的传输给用户
        // 方便模拟，统一存入一个文件中
        Element psk_ID = QID.powZn(s).getImmutable();
        Properties pskProp = new Properties();
        pskProp.setProperty("psk", Base64.getEncoder().encodeToString(psk_ID.toBytes()));
        storePropToFile(pskProp, id + ".properties");
    }

    // 生成用户私钥
    public static void UserKeyGen(String pairingParametersFileName, String pubParamFileName, String id) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        // 从文件中读取公钥
        Properties pkProp = loadPropFromFile(pubParamFileName);
        String PString = pkProp.getProperty("P");

        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        // 生成随机数x，作为用户的私钥
        Element x = bp.getZr().newRandomElement().getImmutable();
        // 计算用户公钥
        Element upk = P.mulZn(x);

        Properties userProp = new Properties();
        userProp.setProperty("usk", Base64.getEncoder().encodeToString(x.toBytes()));
        userProp.setProperty("upk", Base64.getEncoder().encodeToString(upk.toBytes()));
        storePropToFile(userProp, id + ".properties");
    }

    // 签名
    public static Element[] Sign(String pairingParametersFileName, String pubParamFileName, String id, byte[] message)
            throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        // 获取公开参数
        Properties pubProp = loadPropFromFile(pubParamFileName);
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P"))).getImmutable();
        Element P_Pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P_Pub")))
                .getImmutable();

        // 获取用户自己的信息
        Properties userProp = loadPropFromFile(id + ".properties");
        Element upk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(userProp.getProperty("upk")))
                .getImmutable();
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(userProp.getProperty("usk")))
                .getImmutable();
        Element psk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(userProp.getProperty("psk")))
                .getImmutable();

        // 选择随机数
        Element r = bp.getZr().newRandomElement();
        Element U = P.mulZn(r).getImmutable();

        // 获取状态信息，将公开参数作为状态信息
        String p = pubProp.getProperty("P");
        String pPub = pubProp.getProperty("P_Pub");
        byte[] hash = HASH(p + pPub);
        Element Q = hashToG(bp, hash);

        // 计算m, id, upk,U组合的hash值
        byte[] res = hashCombination(message, id.getBytes(), upk.toBytes(), U.toBytes());
        Element h = hashToZ(bp, res);

        Element V = P_Pub.mulZn(x).mulZn(h).add(Q.mulZn(r)).add(psk).getImmutable();

        Element[] sigma = new Element[2];
        sigma[0] = U;
        sigma[1] = V;
        return sigma;
    }

    // 验证
    public static boolean Verify(String pairingParametersFileName, String pubParamFileName, String id, byte[] message,
            Element[] sigma) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        // 使用sha1 将 id 转为QID
        byte[] idHash = HASH(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        // 获取公开参数
        Properties pubProp = loadPropFromFile(pubParamFileName);
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P"))).getImmutable();
        Element P_Pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P_Pub")))
                .getImmutable();

        // 获取状态信息，将公开参数作为状态信息
        String p = pubProp.getProperty("P");
        String pPub = pubProp.getProperty("P_Pub");
        byte[] hash = HASH(p + pPub);
        Element Q = hashToG(bp, hash);

        // 获取用户的公钥，
        Properties userProp = loadPropFromFile(id + ".properties");
        Element upk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(userProp.getProperty("upk")))
                .getImmutable();

        // 计算m, id, upk,U组合的hash值
        byte[] res = hashCombination(message, id.getBytes(), upk.toBytes(), sigma[0].toBytes());

        Element h = hashToZ(bp, res);

        Element left = bp.pairing(sigma[1], P);
        Element right = bp.pairing(QID.add(upk.mulZn(h)), P_Pub).mul(bp.pairing(sigma[0], Q));
        return left.isEqual(right);
    }

    // 聚合签名, U_1,U_2,...,U_n,V
    public static Element[] Aggregate(List<Element[]> sigmaList) {
        Element[] res = new Element[sigmaList.size() + 1];
        Element[] init = sigmaList.get(0);
        res[0] = init[0];
        Element V = init[1];
        for (int i = 1; i < sigmaList.size(); i++) {
            res[i] = sigmaList.get(i)[0];
            V = V.add(sigmaList.get(i)[1]);
        }
        res[sigmaList.size()] = V;
        return res;
    }

    // 聚合签名验证
    // 在验证失败后二分验证O(log2 N)
    public static boolean AggregateVerify(String pairingParametersFileName, String pubParamFileName, String[] idx,
            byte[][] message, Element[] sigma) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element[] QIDX = new Element[idx.length];
        for (int i = 0; i < idx.length; i++) {
            byte[] idHash = HASH(idx[i]);
            Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
            QIDX[i] = QID;
        }

        // 获取公开参数信息
        Properties pubProp = loadPropFromFile(pubParamFileName);
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P"))).getImmutable();
        Element P_Pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P_Pub")))
                .getImmutable();
        String p = pubProp.getProperty("P");
        String pPub = pubProp.getProperty("P_Pub");
        byte[] hash = HASH(p + pPub);
        Element Q = hashToG(bp, hash);

        Element[] PKX = new Element[idx.length];
        for (int i = 0; i < idx.length; i++) {
            Properties userProp = loadPropFromFile(idx[i] + ".properties");
            Element upk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(userProp.getProperty("upk")))
                    .getImmutable();
            PKX[i] = upk;
        }

        Element[] hx = new Element[idx.length];
        for (int i = 0; i < idx.length; i++) {
            byte[] res = hashCombination(message[i], idx[i].getBytes(), PKX[i].toBytes(), sigma[i].toBytes());
            Element h = hashToZ(bp, res);
            hx[i] = h;
        }
        Element left = bp.pairing(sigma[idx.length], P);// V,P配对 1P
        Element U = sigma[0];
        for (int i = 1; i < idx.length; i++) {
            U = U.add(sigma[i]);
        }
        Element part = QIDX[0].add(PKX[0].mulZn(hx[0]));// 1M
        for (int i = 1; i < idx.length; i++) {
            part = part.add(QIDX[i].add(PKX[i].mulZn(hx[i])));// nM
        }
        Element right = bp.pairing(part, P_Pub).mul(bp.pairing(U, Q));// U1+U2+......+Un和Q配对 2P
        return left.isEqual(right);
    }

    // 验证
    public static boolean InvalidVerify(String pairingParametersFileName, String pubParamFileName, String id,
            byte[] message,
            Element[] sigma) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        // 使用sha1 将 id 转为QID
        byte[] idHash = HASH(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        // 获取公开参数
        Properties pubProp = loadPropFromFile(pubParamFileName);
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P"))).getImmutable();
        Element P_Pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pubProp.getProperty("P_Pub")))
                .getImmutable();

        // 获取状态信息，将公开参数作为状态信息
        String p = pubProp.getProperty("P");
        String pPub = pubProp.getProperty("P_Pub");
        byte[] hash = HASH(p + pPub);
        Element Q = hashToG(bp, hash);

        // 获取用户的公钥，
        Properties userProp = loadPropFromFile(id + ".properties");
        Element upk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(userProp.getProperty("upk")))
                .getImmutable();

        // 计算m, id, upk,U组合的hash值
        byte[] res = hashCombination(message, id.getBytes(), upk.toBytes(), sigma[0].toBytes());

        Element h = hashToZ(bp, res);

        Element left = bp.pairing(sigma[1], P);
        Element right = bp.pairing(QID.add(upk.mulZn(h)), P_Pub).mul(bp.pairing(sigma[0], Q));
        return left.isEqual(right);
    }

    // 无效签名
    public static ArrayList<Integer> Inviald(String pairingParametersFileName, String pubParamFileName, String[] idx,
            byte[][] message, List<Element[]> sigmaList) throws NoSuchAlgorithmException {
        ArrayList<Integer> res = new ArrayList<>();
        for (int i = 0; i < idx.length; i++) {
            if (InvalidVerify(pairingParametersFileName, pubParamFileName, idx[i], message[i],
                    sigmaList.get(i)) == false) {
                res.add(i);
            }
        }
        return res;
    }

    // 一种可行的组合方法
    public static byte[] hashCombination(byte[] message, byte[] id, byte[] upk, byte[] U)
            throws NoSuchAlgorithmException {
        int m_len = message.length, id_len = id.length, upk_len = upk.length, u_len = U.length;
        int total_len = m_len + id_len + upk_len + u_len;
        byte[] res = new byte[total_len];
        for (int i = 0; i < m_len; i++) {
            res[i] = message[i];
        }
        for (int i = 0; i < id_len; i++) {
            res[i + m_len] = id[i];
        }
        for (int i = 0; i < upk_len; i++) {
            res[i + m_len + id_len] = upk[i];
        }
        for (int i = 0; i < u_len; i++) {
            res[i + m_len + id_len + upk_len] = U[i];
        }
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(res);
        return instance.digest();
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName, true)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] HASH(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static Element hashToG(Pairing pb, byte[] code) {
        return pb.getG1().newElementFromHash(code, 0, code.length).getImmutable();
    }

    public static Element hashToZ(Pairing pb, byte[] code) {
        return pb.getZr().newElementFromHash(code, 0, code.length).getImmutable();
    }

    public static ArrayList<Integer> getInvalidSign(byte[][] message, String[] idx, List<Element[]> sigmaList)
            throws Exception {
        String dir = "./src/data/";
        String pairingParametersFileName = dir + "a.properties";
        String pubParamFileName = dir + "pub.properties";
        ArrayList<Integer> res = Inviald(pairingParametersFileName, pubParamFileName, idx, message, sigmaList);
        // ArrayList<Element[]> r = new ArrayList<Element[]>();
        // for (Integer integer : res) {
        // r.add(sigmaList.get(integer));
        // }
        return res;
    }

    public static String[] setMessage() {
        Scanner sc = new Scanner(System.in);
        Integer num = 0;
        System.out.println("输入消息个数：");
        num = sc.nextInt();
        sc.nextLine();
        String[] messages = new String[num];
        for (int i = 0; i < num; i++) {
            System.out.println("输入第" + (i + 1) + "个消息：");
            messages[i] = sc.nextLine();
        }
        sc.close();
        return messages;
    }

    public static String[] setIds() {
        return null;
    }

    // 设置签名
    public static ArrayList<Element[]> setSign(String pairingParametersFileName, String[] ids, String pubParamFileName,
            String KGCFileName, String[] m) throws Exception {
        for (int i = 0; i < ids.length; i++) {
            ids[i] = i + "@example.com";
        }

        for (int i = 0; i < ids.length; i++) {
            PartialPrivateKeyGen(pairingParametersFileName, ids[i], KGCFileName);
            UserKeyGen(pairingParametersFileName, pubParamFileName, ids[i]);
            UserKeyGen(pairingParametersFileName, pubParamFileName, ids[i]);
        }
        ArrayList<Element[]> signas = new ArrayList<>();
        for (int i = 0; i < ids.length; i++) {
            signas.add(Sign(pairingParametersFileName, pubParamFileName, ids[i], m[i].getBytes()));
        }
        return signas;
    }

    // 获取ids
    public static String[] getIds(String[] messages) {
        String[] ids = new String[messages.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = i + "@example.com";
        }
        return ids;
    }

    public static byte[][] getByte(String[] m, String[] ids) {
        byte[][] messages = new byte[m.length][];
        for (int i = 0; i < ids.length; i++) {
            messages[i] = m[i].getBytes();
        }
        return messages;
    }

    // 获取验证
    public static boolean getVerify(Element[] signs, String[] m, String[] ids,
            String pairingParametersFileName, String pubParamFileName) throws Exception {
        // Element[] aggSigns = Aggregate(signs);
        byte[][] messages = new byte[m.length][];
        for (int i = 0; i < ids.length; i++) {
            messages[i] = m[i].getBytes();
        }
        return AggregateVerify(pairingParametersFileName, pubParamFileName, ids, messages, signs);
    }

    // Swing框架调用签名
    public static Element[] SwingSign(String[] messages) throws Exception {
        mysigmaList = new ArrayList<>();
        String[] ids = new String[messages.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = i + "@example.com";
        }
        String dir = "./src/data/";
        String pairingParametersFileName = dir + "a.properties";
        String pubParamFileName = dir + "pub.properties";
        String KGCFileName = dir + "kgc.properties";
        mysigmaList = setSign(pairingParametersFileName, ids, pubParamFileName, KGCFileName, messages);
        // 聚合签名返回
        Element[] aggSigns = Aggregate(mysigmaList);
        return aggSigns;
    }

    // SwingVerify调用验证
    public static boolean SwingVerify(Element[] signs, String[] m, String[] ids) throws Exception {
        String dir = "./src/data/";
        String pairingParametersFileName = dir + "a.properties";
        String pubParamFileName = dir + "pub.properties";
        return getVerify(signs, m, ids, pairingParametersFileName, pubParamFileName);
    }

    public static ArrayList<Integer> SwingGetInvalid(String[] m, String[] ids)
            throws Exception {
        long startTime = System.currentTimeMillis();
        byte[][] message = getByte(m, ids);
        ArrayList<Integer> r = getInvalidSign(message, ids, mysigmaList);
        long endTime = System.currentTimeMillis();
        long elapsedTime = endTime - startTime;
        System.out.println("程序运行时间（毫秒）: " + elapsedTime);
        return r;
    }

    private static int binarySearchForInvalidSignature(List<Element[]> sigmaList, String[] idx, byte[][] message,
            String pairingParametersFileName, String pubParamFileName) throws Exception {
        long startTime = System.currentTimeMillis();
        if (sigmaList.isEmpty()) {
            return -1;
        }
        List<Element[]> signaList = sigmaList;
        int low = 0;
        int high = signaList.size() - 1;
        while (low <= high) {
            int mid = low + (high - low) / 2;

            // // 获取当前中间位置的签名
            // Element[] currentSignature = sigmaList.get(mid);

            // 创建左右子数组
            if (signaList.size() == 1) {
                return mid;
            }
            List<Element[]> leftSignatures = signaList.subList(0, mid + 1);
            List<Element[]> rightSignatures = signaList.subList(mid + 1, signaList.size());
            // 分配左右子数组的元素
            String[] leftIds = Arrays.copyOfRange(idx, low, mid + 1);
            String[] rightIds = Arrays.copyOfRange(idx, mid + 1, high);
            byte[][] leftMessages = Arrays.copyOfRange(message, low, mid + 1);
            byte[][] rightMessages = Arrays.copyOfRange(message, mid + 1, high);

            // 聚合左子数组的签名
            Element[] leftAggregatedSignature = leftSignatures.isEmpty() ? new Element[0] : Aggregate(leftSignatures);

            // 聚合右子数组的签名
            Element[] rightAggregatedSignature = rightSignatures.isEmpty() ? new Element[0]
                    : Aggregate(rightSignatures);

            // 验证聚合后的签名
            boolean leftVerify = AggregateVerify(pairingParametersFileName, pubParamFileName, leftIds,
                    leftMessages, leftAggregatedSignature);
            boolean rightVerify = AggregateVerify(pairingParametersFileName, pubParamFileName, rightIds,
                    rightMessages, rightAggregatedSignature);

            System.out.println("二分签名验证：左子数组 " + leftVerify + "，右子数组 " + rightVerify);

            // 如果右子数组验证通过，无效签名在左子数组
            if (rightVerify) {
                high = mid;
                System.out.println(signaList.size());
            } else {
                // 输出无效签名对应的信息
                long endTime = System.currentTimeMillis();
                long elapsedTime = endTime - startTime;
                System.out.println("程序运行时间（毫秒）: " + elapsedTime);
                return mid;
            }
        }
        long endTime = System.currentTimeMillis();
        long elapsedTime = endTime - startTime;
        System.out.println("程序运行时间（毫秒）: " + elapsedTime);
        return -1; // 未找到无效签名
    }
    // private static List<Integer> binarySearchForInvalidSignatures(List<Element[]>
    // sigmaList, String[] idx, byte[][] message,
    // String pairingParametersFileName, String pubParamFileName, int low, int high)
    // throws Exception {
    // long startTime = System.currentTimeMillis();
    // List<Integer> invalidIndices = new ArrayList<>();

    // if (sigmaList.isEmpty() || low > high) {
    // return invalidIndices;
    // }

    // int mid = low + (high - low) / 2;

    // // 创建左右子数组
    // List<Element[]> leftSignatures = sigmaList.subList(0, mid + 1);
    // List<Element[]> rightSignatures = sigmaList.subList(mid + 1,
    // sigmaList.size());
    // // 分配左右子数组的元素
    // String[] leftIds = Arrays.copyOfRange(idx, low, mid + 1);
    // String[] rightIds = Arrays.copyOfRange(idx, mid + 1, high);
    // byte[][] leftMessages = Arrays.copyOfRange(message, low, mid + 1);
    // byte[][] rightMessages = Arrays.copyOfRange(message, mid + 1, high);

    // // 聚合左子数组的签名
    // Element[] leftAggregatedSignature = leftSignatures.isEmpty() ? new Element[0]
    // : Aggregate(leftSignatures);

    // // 聚合右子数组的签名
    // Element[] rightAggregatedSignature = rightSignatures.isEmpty() ? new
    // Element[0] : Aggregate(rightSignatures);

    // // 验证聚合后的签名
    // boolean leftVerify = AggregateVerify(pairingParametersFileName,
    // pubParamFileName, leftIds,
    // leftMessages, leftAggregatedSignature);
    // boolean rightVerify = AggregateVerify(pairingParametersFileName,
    // pubParamFileName, rightIds,
    // rightMessages, rightAggregatedSignature);

    // System.out.println("二分签名验证：左子数组 " + leftVerify + "，右子数组 " + rightVerify);

    // // 如果右子数组验证通过，无效签名在左子数组
    // if (rightVerify) {
    // invalidIndices.addAll(binarySearchForInvalidSignatures(sigmaList, idx,
    // message, pairingParametersFileName,
    // pubParamFileName, low, mid));
    // } else {
    // // 输出无效签名对应的信息
    // invalidIndices.add(mid);
    // }

    // // 继续在左子数组中查找
    // invalidIndices.addAll(binarySearchForInvalidSignatures(sigmaList, idx,
    // message, pairingParametersFileName,
    // pubParamFileName, low, mid - 1));

    // // 继续在右子数组中查找
    // invalidIndices.addAll(binarySearchForInvalidSignatures(sigmaList, idx,
    // message, pairingParametersFileName,
    // pubParamFileName, mid + 1, high));

    // long endTime = System.currentTimeMillis();
    // long elapsedTime = endTime - startTime;
    // System.out.println("程序运行时间（毫秒）: " + elapsedTime);

    // return invalidIndices;
    // }

    public static void main(String[] args) throws Exception {
        String dir = "./src/data/";
        String pairingParametersFileName = dir + "a.properties";
        String idAlice = "alice@example.com";
        String idBob = "bob@example.com";
        String idC = "c@example.com";
        String idD = "d@example.com";
        String idE = "E@example.com";
        String idF = "F@example.com";
        String idG = "G@example.com";
        String idH = "H@example.com";
        String idI = "I@example.com";
        String idJ = "J@example.com";
        String pubParamFileName = dir + "pub.properties";
        String KGCFileName = dir + "kgc.properties";
        KeyGen(pairingParametersFileName, pubParamFileName, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idAlice, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idBob, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idC, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idD, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idE, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idF, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idG, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idH, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idI, KGCFileName);
        PartialPrivateKeyGen(pairingParametersFileName, idJ, KGCFileName);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idAlice);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idBob);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idC);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idD);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idE);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idF);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idG);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idH);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idI);
        UserKeyGen(pairingParametersFileName, pubParamFileName, idJ);

        String message_a = "Alice,This is a message from Alice!";
        String message_b = "Bob,This is a message from Bob!";
        String message_c = "C,This is a message from C!";
        String message_d = "D,This is a message from D!";
        String message_e = "E,This is a message from E!";
        String message_f = "F,This is a message from F!";
        String message_g = "G,This is a message from G!";
        String message_h = "H,This is a message from H!";
        String message_i = "I,This is a message from I!";
        String message_j = "J,This is a message from J!";
        Element[] sigma1 = Sign(pairingParametersFileName, pubParamFileName, idAlice, message_a.getBytes());
        Element[] sigma2 = Sign(pairingParametersFileName, pubParamFileName, idBob, message_b.getBytes());
        Element[] sigma3 = Sign(pairingParametersFileName, pubParamFileName, idC, message_c.getBytes());
        Element[] sigma4 = Sign(pairingParametersFileName, pubParamFileName, idD, message_d.getBytes());
        Element[] sigma5 = Sign(pairingParametersFileName, pubParamFileName, idE, message_e.getBytes());
        Element[] sigma6 = Sign(pairingParametersFileName, pubParamFileName, idF, message_f.getBytes());
        Element[] sigma7 = Sign(pairingParametersFileName, pubParamFileName, idG, message_g.getBytes());
        Element[] sigma8 = Sign(pairingParametersFileName, pubParamFileName, idG, message_g.getBytes());
        Element[] sigma9 = Sign(pairingParametersFileName, pubParamFileName, idI, message_i.getBytes());
        Element[] sigma10 = Sign(pairingParametersFileName, pubParamFileName, idJ, message_j.getBytes());
        boolean result = Verify(pairingParametersFileName, pubParamFileName, idAlice, message_a.getBytes(), sigma1);
        System.out.println("Alice 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idBob, message_b.getBytes(), sigma2);
        System.out.println("Bob 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idC, message_c.getBytes(), sigma3);
        System.out.println("C 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idD, message_d.getBytes(), sigma4);
        System.out.println("D 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idE, message_e.getBytes(), sigma5);
        System.out.println("E 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idF, message_f.getBytes(), sigma6);
        System.out.println("F 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idG, message_g.getBytes(), sigma7);
        System.out.println("G 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idH, message_h.getBytes(), sigma8);
        System.out.println("H 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idI, message_i.getBytes(), sigma9);
        System.out.println("I 验证签名通过？ " + result);
        result = Verify(pairingParametersFileName, pubParamFileName, idJ, message_j.getBytes(), sigma10);
        System.out.println("J 验证签名通过？ " + result);
        List<Element[]> sigmaList = new ArrayList<>();
        sigmaList.add(sigma1);
        sigmaList.add(sigma2);
        sigmaList.add(sigma3);
        sigmaList.add(sigma4);
        sigmaList.add(sigma5);
        sigmaList.add(sigma6);
        sigmaList.add(sigma7);
        sigmaList.add(sigma8);
        sigmaList.add(sigma9);
        sigmaList.add(sigma10);
        Element[] SIGMA = Aggregate(sigmaList);
        String[] idx = { idAlice, idBob, idC, idD, idE, idF, idG, idH, idI, idJ };
        byte[][] message = { message_a.getBytes(), message_b.getBytes(), message_c.getBytes(), message_d.getBytes(),
                message_e.getBytes(), message_f.getBytes(), message_g.getBytes(), message_h.getBytes(),
                message_i.getBytes(), message_j.getBytes() };
        boolean Aggres = AggregateVerify(pairingParametersFileName, pubParamFileName, idx, message, SIGMA);
        System.out.println("聚合签名验证通过？ " + Aggres);
        message[5][0] = 1;// 假如消息被篡改

        // 使用二分查找找到无效签名
        int invalidSignatureIndex = binarySearchForInvalidSignature(sigmaList, idx, message, pairingParametersFileName,
                pubParamFileName);

        // 输出结果
        if (invalidSignatureIndex != -1) {
            System.out.println("无效签名在索引 " + invalidSignatureIndex);
            System.out.println("对应的 id 为 " + idx[invalidSignatureIndex]);
            System.out.println("对应的消息为 " + new String(message[invalidSignatureIndex]));
        } else {
            System.out.println("未找到无效签名");
        }
        // ArrayList<Integer> res = Inviald(pairingParametersFileName, pubParamFileName,
        // idx, message, sigmaList);

        // 返回无效的签名
        // if (!Aggres) {
        // ArrayList<Element[]> r = getInvalidSign1(message, idx, sigmaList);
        // for (Element[] elements : r) {
        // for (Element e : elements) {
        // System.out.println(e);
        // }
        // }
        // }
    }
}