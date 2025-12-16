import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Main {

    /**
     * 密钥生成相关方法
     */
    // 生成指定位数的随机数（这里指二进制位数）
    public static BigInteger CreateBigInteger(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger randomNumber;
        do {
            // 生成指定位数的随机数
            randomNumber = new BigInteger(bitLength, random);
        } while (randomNumber.bitLength() != bitLength);
        return randomNumber;
    }

    // 生成[min, max]范围内的随机数
    public static BigInteger CreateBigIntegerInRange(BigInteger min, BigInteger max) {
        SecureRandom random = new SecureRandom();
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(range.bitLength(), random);
        } while (randomNumber.compareTo(range) >= 0);
        return min.add(randomNumber);
    }

    // 模幂运算（快速幂）
    public static BigInteger GetMod(BigInteger base, BigInteger exp, BigInteger modulus) {
        return base.modPow(exp, modulus);
    }

    // Miller-Rabin素性测试
    public static boolean MillerRabin(BigInteger n, int iterations) {
        if (n.compareTo(BigInteger.TWO) < 0) return false;
        if (n.compareTo(BigInteger.TWO) == 0) return true;
        if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;

        // 将n-1写成d*2^s的形式
        BigInteger d = n.subtract(BigInteger.ONE);
        int s = 0;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.divide(BigInteger.TWO);
            s++;
        }

        SecureRandom random = new SecureRandom();
        for (int i = 0; i < iterations; i++) {
            // 选择[2, n-2]范围内的随机数
            BigInteger a = CreateBigIntegerInRange(BigInteger.TWO, n.subtract(BigInteger.TWO));

            // 计算x = a^d mod n
            BigInteger x = a.modPow(d, n);

            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
                continue;
            }

            boolean continueLoop = false;
            for (int j = 1; j < s; j++) {
                x = x.modPow(BigInteger.TWO, n);
                if (x.equals(BigInteger.ONE)) {
                    return false;
                }
                if (x.equals(n.subtract(BigInteger.ONE))) {
                    continueLoop = true;
                    break;
                }
            }

            if (!continueLoop) {
                return false;
            }
        }
        return true;
    }

    // 生成指定范围内的素数
    public static BigInteger GeneratePrimeInRange(BigInteger min, BigInteger max, int iterations) {
        SecureRandom random = new SecureRandom();
        BigInteger candidate;
        do {
            // 生成范围内的随机奇数
            BigInteger range = max.subtract(min);
            candidate = new BigInteger(range.bitLength(), random);
            if (candidate.compareTo(range) > 0) {
                candidate = candidate.mod(range);
            }
            candidate = min.add(candidate);

            // 确保是奇数
            if (candidate.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                candidate = candidate.add(BigInteger.ONE);
            }

            // 确保在范围内
            if (candidate.compareTo(min) < 0) candidate = min;
            if (candidate.compareTo(max) > 0) candidate = max;

        } while (!MillerRabin(candidate, iterations));

        return candidate;
    }

    // 扩展欧几里得算法
    public static class EuclidResult {
        public BigInteger gcd;
        public BigInteger x;
        public BigInteger y;

        public EuclidResult(BigInteger gcd, BigInteger x, BigInteger y) {
            this.gcd = gcd;
            this.x = x;
            this.y = y;
        }
    }

    public static EuclidResult ExtendedEuclid(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new EuclidResult(a, BigInteger.ONE, BigInteger.ZERO);
        }

        EuclidResult result = ExtendedEuclid(b, a.mod(b));
        return new EuclidResult(
                result.gcd,
                result.y,
                result.x.subtract(a.divide(b).multiply(result.y))
        );
    }

    /**
     * 生成RSA密钥对
     */
    public static RSAKeyPair GenerateRSAKeys() {
        // 1. 生成p和q（不小于14位二进制，即4位十进制数）
        // 对应十进制范围：1000 - 16383（2^13 = 8192，2^14 = 16384）
        // 但为了确保是4位数，我们选择1000-9999范围

        BigInteger minPrime = new BigInteger("1000");      // 最小值
        BigInteger maxPrime = new BigInteger("9999");      // 最大值

        System.out.println("正在生成素数p...");
        BigInteger p = GeneratePrimeInRange(minPrime, maxPrime, 10);

        System.out.println("正在生成素数q...");
        BigInteger q;
        do {
            q = GeneratePrimeInRange(minPrime, maxPrime, 10);
            // 确保p和q不相等且距离不要太近
            // 这里要求|p-q| > 1000，确保距离
        } while (q.equals(p) || p.subtract(q).abs().compareTo(new BigInteger("1000")) < 0);

        System.out.println("p = " + p + " (长度: " + p.bitLength() + " bits)");
        System.out.println("q = " + q + " (长度: " + q.bitLength() + " bits)");

        // 2. 计算n和φ(n)
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        System.out.println("n = p * q = " + n);
        System.out.println("φ(n) = (p-1)*(q-1) = " + phi);

        // 3. 选择e（1 < e < φ(n)，且e与φ(n)互质）
        // 不要选择太小的数如3, 7, 11等，这里选择从65537开始尝试
        // 或者随机选择一个合适的e
        BigInteger e = null;

        // 尝试常用素数
        BigInteger[] commonE = {
                // 常用选择
                new BigInteger("17"),
                new BigInteger("19"),
                new BigInteger("23"),
                new BigInteger("29"),
                new BigInteger("31"),
                new BigInteger("65537")
        };

        boolean foundE = false;
        for (BigInteger candidateE : commonE) {
            if (candidateE.compareTo(phi) < 0 &&
                    candidateE.gcd(phi).equals(BigInteger.ONE)) {
                e = candidateE;
                foundE = true;
                System.out.println("选择常用e值: " + e);
                break;
            }
        }

        // 如果常用值都不行，随机生成一个
        if (!foundE) {
            System.out.println("常用e值不适用，正在随机生成e...");
            SecureRandom random = new SecureRandom();
            do {
                // 生成一个比φ(n)小但不要太小的随机数
                // 为了避免太小，我们生成一个位数约为φ(n)一半的随机数
                int bitLength = phi.bitLength() / 2;
                if (bitLength < 5) bitLength = 5; // 确保至少有5位

                e = new BigInteger(bitLength, random);
                // 确保e > 1 且 e < φ(n) 且 与φ(n)互质
                if (e.compareTo(BigInteger.ONE) <= 0) {
                    e = e.add(BigInteger.TWO); // 确保大于1
                }
            } while (e.compareTo(phi) >= 0 ||
                    !e.gcd(phi).equals(BigInteger.ONE));
            System.out.println("随机生成e值: " + e);
        }

        // 4. 计算d（e关于φ(n)的模逆）
        EuclidResult result = ExtendedEuclid(e, phi);
        BigInteger d = result.x.mod(phi);
        if (d.compareTo(BigInteger.ZERO) < 0) {
            d = d.add(phi);
        }

        System.out.println("e = " + e + " (长度: " + e.bitLength() + " bits)");
        System.out.println("d = " + d + " (长度: " + d.bitLength() + " bits)");

        return new RSAKeyPair(n, e, d);
    }

    // RSA密钥对类
    public static class RSAKeyPair {
        public BigInteger n;
        public BigInteger e;
        public BigInteger d;

        public RSAKeyPair(BigInteger n, BigInteger e, BigInteger d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }
    }

    /**
     * 文件操作相关方法（保持不变）
     */
    public static String ReadFileToString(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        byte[] bytes = Files.readAllBytes(path);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public static void WriteStringToFile(String content, String filePath) {
        Path path = Paths.get(filePath);
        try {
            Files.write(path, content.getBytes(), StandardOpenOption.CREATE);
        } catch (IOException e) {
            System.err.println("写入文件错误: " + e.getMessage());
        }
    }

    /**
     * 文本编码相关方法（保持不变）
     */
    public static String ConvertTextToCode(String text) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (!Character.isLetterOrDigit(ch)) {
                continue;
            }
            int number;
            if (Character.isDigit(ch)) {
                number = ch - '0';
            } else if (Character.isLowerCase(ch)) {
                number = ch - 'a' + 10;
            } else {
                number = ch - 'A' + 36;
            }
            result.append(String.format("%02d", number));
        }
        return result.toString();
    }

    public static String ConvertCodeToText(String text) {
        StringBuilder result = new StringBuilder();
        int startIndex = 0;
        while (startIndex < text.length()) {
            String tmp = text.substring(startIndex, startIndex + 2);
            int number = Integer.parseInt(tmp);
            if (number <= 9) {
                result.append((char)(number + '0'));
            } else if (number <= 35) {
                result.append((char)(number - 10 + 'a'));
            } else if (number <= 61) {
                result.append((char)(number - 36 + 'A'));
            }
            startIndex = startIndex + 2;
        }
        return result.toString();
    }

    /**
     * 加密解密相关方法（保持不变）
     */
    public static String RSAEN(String text, BigInteger exp, BigInteger modulus,
                               int applynumber, int length, int group) {
        StringBuilder result = new StringBuilder();
        int startIndex = 0;
        String demoText;
        if (text.length() % group == 0) {
            demoText = text;
        } else {
            demoText = text + String.format("%02d", applynumber);
        }
        while (startIndex < demoText.length()) {
            String tmpNumber = demoText.substring(startIndex, startIndex + group);
            int number = Integer.parseInt(tmpNumber);
            BigInteger base = BigInteger.valueOf(number);
            BigInteger mod = GetMod(base, exp, modulus);
            String modString = mod.toString();
            StringBuilder zeros = new StringBuilder();
            int tmp = 0;
            while (modString.length() + tmp < length) {
                zeros.append("0");
                tmp = tmp + 1;
            }
            result.append(zeros).append(modString);
            startIndex = startIndex + group;
        }
        return result.toString();
    }

    public static String RSADE(String text, BigInteger exp, BigInteger modulus,
                               int length, int group) {
        StringBuilder result = new StringBuilder();
        int startIndex = 0;
        while (startIndex < text.length()) {
            String tmpNumber = text.substring(startIndex, startIndex + length);
            BigInteger base = new BigInteger(tmpNumber);
            BigInteger mod = GetMod(base, exp, modulus);
            String modString = mod.toString();
            StringBuilder zeros = new StringBuilder();
            int tmp = 0;
            while (modString.length() + tmp < group) {
                zeros.append("0");
                tmp = tmp + 1;
            }
            result.append(zeros).append(modString);
            startIndex = startIndex + length;
        }
        return result.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // 生成RSA密钥对
        System.out.println("=== 生成RSA密钥对 ===");
        RSAKeyPair keyPair = GenerateRSAKeys();

        System.out.println("\n=== 密钥信息 ===");
        System.out.println("公钥: (e = " + keyPair.e + ", n = " + keyPair.n + ")");
        System.out.println("私钥: (d = " + keyPair.d + ", n = " + keyPair.n + ")");
        System.out.println("n的位数: " + keyPair.n.bitLength() + " bits");

        // 文件路径
        String readPath = "../lab2-Plaintext.txt";
        String RSAENPath = "../RSAEN_lab2-Plaintext.txt";
        String RSADEPath = "../RSADE_lab2-Plaintext.txt";

        // 加密参数
        int applyNumber = 99;
        int group = 4;          // 分组长度
        int cipherLength = keyPair.n.toString().length(); // 密文长度根据n的长度确定

        System.out.print("\n是否要进行加密？(Y/N): ");
        String in = scanner.nextLine();

        String initText = null;
        String RSAENText = null;
        String RSADEText = null;

        if (in.equalsIgnoreCase("Y")) {
            System.out.println("开始加密...");
            try {
                // 读取文件
                String text = ReadFileToString(readPath);
                System.out.println("原始文本: " + text.substring(0, Math.min(text.length(), 50)) + "...");

                // 编码处理文本
                initText = ConvertTextToCode(text);
                System.out.println("编码后文本: " + initText.substring(0, Math.min(initText.length(), 50)) + "...");

                // 加密
                RSAENText = RSAEN(initText, keyPair.e, keyPair.n, applyNumber, cipherLength, group);

                // 写入加密文件
                WriteStringToFile(RSAENText, RSAENPath);
                System.out.println("加密完成！密文已保存到: " + RSAENPath);
                System.out.println("密文长度: " + RSAENText.length() + " 字符");

            } catch (IOException e) {
                System.err.println("读取文件错误: " + e.getMessage());
            }
        }

        System.out.print("\n是否要进行解密？(Y/N): ");
        String in2 = scanner.nextLine();

        if (in2.equalsIgnoreCase("Y")) {
            System.out.println("开始解密...");
            try {
                // 读取加密文件
                String cipherText = ReadFileToString(RSAENPath);
                System.out.println("读取密文长度: " + cipherText.length() + " 字符");

                // 解密
                String decryptedCode = RSADE(cipherText, keyPair.d, keyPair.n, cipherLength, group);

                // 解码为文本
                RSADEText = ConvertCodeToText(decryptedCode);

                // 写入解密文件
                WriteStringToFile(RSADEText, RSADEPath);
                System.out.println("解密完成！明文已保存到: " + RSADEPath);
                System.out.println("解密后文本: " + RSADEText.substring(0, Math.min(RSADEText.length(), 50)) + "...");

            } catch (IOException e) {
                System.err.println("读取文件错误: " + e.getMessage());
            }
        }

        System.out.print("\n是否要进行比对检验？(Y/N): ");
        String in3 = scanner.nextLine();

        if (in3.equalsIgnoreCase("Y")) {
            try {
                String originalText = ReadFileToString(readPath);
                originalText = ConvertTextToCode(originalText);

                if (RSADEText != null && initText != null) {
                    String decryptedCode = ConvertTextToCode(RSADEText);

                    // 注意：解密后的文本可能包含填充，需要处理
                    if (decryptedCode.startsWith(initText)) {
                        System.out.println("比对成功！前后文本一致");
                    } else {
                        System.out.println("比对失败！前后文本不一致");
                        System.out.println("原始编码: " + initText.substring(0, Math.min(initText.length(), 50)) + "...");
                        System.out.println("解密编码: " + decryptedCode.substring(0, Math.min(decryptedCode.length(), 50)) + "...");
                    }
                } else {
                    System.out.println("无法比对：缺少必要的文本数据");
                }
            } catch (IOException e) {
                System.err.println("读取文件错误: " + e.getMessage());
            }
        }

        scanner.close();
        System.out.println("\n程序结束。");
    }
}