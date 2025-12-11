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
     * CreateBigInteger、CreateBigIntegerInRange、GetMod、JudgeMod、MillerRabin、LargePrimeNumber、ExtendedEuclid
     */
    //随机生成n位的大素数
    public static BigInteger CreateBigInteger(int length){
        SecureRandom random = new SecureRandom();
        BigInteger randomNumber;
        do {
            // 生成随机数，位数等于length，将最高位设置为1
            randomNumber = new BigInteger(length-1, random).setBit(length-1); //设置高位
            randomNumber = randomNumber.setBit(0); //设置最低位为1，确保是奇数
        } while (randomNumber.bitLength() != length); //确保长度与length相同
        return randomNumber;
    }

    //生成给定范围内的大随机数，[2,n-2]
    public static BigInteger CreateBigIntegerInRange(BigInteger maxNumber){
        SecureRandom random = new SecureRandom();
        BigInteger min = BigInteger.TWO;
        BigInteger max = maxNumber.subtract(BigInteger.TWO);
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(max.bitLength(), random); // 生成一个位长度与max相同的随机数
        } while (randomNumber.compareTo(min) < 0 || randomNumber.compareTo(max) > 0);
        return randomNumber;
    }

    //计算模乘
    public static BigInteger GetMod(BigInteger base, BigInteger exp, BigInteger modulus){
        BigInteger y = BigInteger.ONE;
        while(true){
            if(exp.compareTo(BigInteger.ZERO) == 0){
                return y;
            }
            while(exp.compareTo(BigInteger.ZERO) > 0 && exp.mod(BigInteger.TWO).equals(BigInteger.ZERO)){
                base = base.pow(2).mod(modulus);
                exp = exp.divide(BigInteger.TWO);
            }
            exp = exp.subtract(BigInteger.ONE);
            y = y.multiply(base).mod(modulus);
        }
    }

    //判断模是否为某个数
    public static boolean JudgeMod(BigInteger mode, BigInteger number){
        return mode.equals(number);
    }

    //Miller-Rabin算法
    public static boolean MillerRabin(BigInteger bigInteger){
        BigInteger n = bigInteger;
        //计算s和d
        int s = 0;
        BigInteger d;
        n = n.subtract(BigInteger.ONE);
        while(n.mod(BigInteger.TWO).equals(BigInteger.ZERO)){
            n = n.divide(BigInteger.TWO);
            s += 1;
        }
        d = n;
        int time = 1;
        int LoopTime = 10;  //循环次数
        while(time <= LoopTime){
            BigInteger a = CreateBigIntegerInRange(bigInteger);
            BigInteger modeNumber = GetMod(a,d,bigInteger);
            if(JudgeMod(modeNumber,BigInteger.ONE) | JudgeMod(modeNumber,bigInteger.subtract(BigInteger.ONE))){
                time = time + 1;
            }
            else{
                for (int tmp = 1;tmp <= s-1;tmp ++){
                    modeNumber = modeNumber.pow(2);
                    modeNumber = modeNumber.mod(bigInteger);
                    if(JudgeMod(modeNumber,bigInteger.subtract(BigInteger.ONE))){
                        time = time + 1;
                        break;
                    }
                }
                time = time + LoopTime + 1;   //若均不满足，说明是合数，给time加一个大数
            }
        }
        return time == LoopTime + 1;
    }

    //生成大素数的算法
    public static BigInteger LargePrimeNumber(int length){
        BigInteger bigInteger;
        while(true){
            bigInteger = CreateBigInteger(length);
            if(MillerRabin(bigInteger)){
                return bigInteger;
            }
        }
    }

    //拓展欧几里得算法
    public static Euclid ExtendedEuclid(BigInteger a, BigInteger b){
        if(b.equals(BigInteger.ZERO)){
            return new Euclid(a,BigInteger.ONE,BigInteger.ZERO);
        }
        Euclid euclid = ExtendedEuclid(b,a.mod(b));
        BigInteger gcd = euclid.gcd;
        BigInteger x1 = euclid.x;
        BigInteger y1 = euclid.y;
        BigInteger x = y1;
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));
        return new Euclid(gcd,x,y);
    }

    /**
     * 文件操作相关方法
     * ReadFileToString、WriteStringToFile
     */
    //读取文件并转化为String类型
    public static String ReadFileToString(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        //使用 Files.readAllBytes() 方法读取文件的所有字节
        byte[] bytes = Files.readAllBytes(path);
        //将字节转换为字符串
        return new String(bytes, StandardCharsets.UTF_8);
    }

    //将String输出到指定路径的文件，不存在则创建
    public static void WriteStringToFile(String content, String filePath) {
        Path path = Paths.get(filePath);
        try {
            Files.write(path, content.getBytes(), StandardOpenOption.CREATE);
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }

    /**
     * 文本编码相关方法
     * ConvertTextToCode、ConvertCodeToText
     */
    //将文本转化为编码
    public static String ConvertTextToCode(String text){
        StringBuilder result = new StringBuilder();
        //遍历字符串中的每个字符
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (!Character.isLetterOrDigit(ch)) {
                continue;
            }
            int number;
            if (Character.isDigit(ch)) {
                number = ch - '0';
            }
            else if (Character.isLowerCase(ch)) {
                number = ch - 'a' + 10;
            }
            else {
                number = ch - 'A' + 36;
            }
            result.append(String.format("%02d", number));
        }
        return result.toString();
    }

    //将编码转化为文本
    public static String ConvertCodeToText(String text){
        StringBuilder result = new StringBuilder();
        int startIndex = 0;
        while (startIndex < text.length()) {
            String tmp = text.substring(startIndex,startIndex+2);
            int number = Integer.parseInt(tmp);
            if (number <= 9){
                result.append((char)(number + '0'));
            }
            else if (number <= 35){
                result.append((char)(number - 10 + 'a'));
            }
            else if (number <= 61){
                result.append((char)(number - 36 + 'A'));
            }
            startIndex = startIndex + 2;
        }
        return result.toString();
    }

    /**
     * 加密、解密相关方法
     * RSAEN、RSADE
     */
    //加密函数
    public static String RSAEN(String text,BigInteger exp,BigInteger modulus,int applynumber,int length,int group){
        StringBuilder result = new StringBuilder();
        int startIndex = 0;
        String demoText;
        if (text.length() % group == 0){
            demoText = text;
        }
        else{
            demoText = text + String.format("%02d", applynumber);                 //不足4则加上补充数字
        }
        while (startIndex < demoText.length()) {
            String tmpNumber = demoText.substring(startIndex,startIndex+group);   //截出一部分进行操作
            int number = Integer.parseInt(tmpNumber);
            BigInteger base = BigInteger.valueOf(number);
            BigInteger mod = GetMod(base,exp,modulus);
            String modString = mod.toString();
            StringBuilder zeros = new StringBuilder();
            int tmp = 0;
            while(modString.length() + tmp<length){
                zeros.append("0");
                tmp = tmp + 1;
            }
            result.append(zeros).append(modString);                               //在前面补0
            startIndex = startIndex + group;
        }
        return result.toString();
    }

    //解密函数
    public static String RSADE(String text,BigInteger exp,BigInteger modulus,int length,int group){
        StringBuilder result = new StringBuilder();
        int startIndex = 0;
        while (startIndex < text.length()) {
            String tmpNumber = text.substring(startIndex,startIndex+length);    //截出一部分操作
            BigInteger base = new BigInteger(tmpNumber);
            BigInteger mod = GetMod(base,exp,modulus);
            String modString = mod.toString();
            StringBuilder zeros = new StringBuilder();
            int tmp = 0;
            while(modString.length() + tmp<group){
                zeros.append("0");
                tmp = tmp + 1;
            }
            result.append(zeros).append(modString);                              //在前面补0
            startIndex = startIndex + length;
        }
        return result.toString();
    }

    public static void main(String[] args) {
        int length = 130;      //指定生成的大素数的位数
        //生成p、q、n、e、d
        BigInteger p = LargePrimeNumber(length);
        BigInteger q = LargePrimeNumber(length);
        BigInteger n = p.multiply(q);
        BigInteger fai = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        BigInteger e = LargePrimeNumber(length);
        BigInteger gcd = ExtendedEuclid(e,fai).gcd;
        while(!gcd.equals(BigInteger.ONE)){
            e = LargePrimeNumber(length);
            gcd = ExtendedEuclid(e,fai).gcd;
        }
        BigInteger d = ExtendedEuclid(e,fai).x.mod(fai).add(fai);
        System.out.println("p="+p+"\nq="+q+"\nn="+n+"\ne="+e+"\nd="+d+"\nfai="+fai);
        System.out.println("公钥为：(e="+e+"，n="+n+")");
        System.out.println("私钥为：(d="+d+"，n="+n+")");
        System.out.println("p的长度为："+p.bitLength()+" q的长度为："+q.bitLength()+" n的长度为："+n.bitLength()+" e的长度为："+e.bitLength()+" d的长度为："+d.bitLength());
        String readPath = "../lab2-Plaintext.txt";         //读取文件的路径
        String RSAENPath = "../RSAEN_lab2-Plaintext.txt";  //写文件的路径
        String RSADEPath = "../RSADE_lab2-Plaintext.txt";  //写文件的路径
        Scanner scanner = new Scanner(System.in);
        System.out.print("是否要进行加密？Y/N");
        String in = scanner.nextLine();
        int applyNumber = 99;  //明文不足时补充的数字
        int group = 4;         //明文的分组长度
        String initText = null;
        String RSAENText;
        String RSADEText = null;
        if(in.equals("Y")){
            System.out.println("加密开始！");
            //读取文件
            String text = null;
            try{
                text = ReadFileToString(readPath);
            }catch (IOException msg){
                msg.printStackTrace();
            }
            //编码处理文本
            assert text != null;
            initText = ConvertTextToCode(text);
            //加密
            RSAENText = RSAEN(initText,e,n,applyNumber,length,group);
            //将加密后文本输出到指定路径
            WriteStringToFile(RSAENText,RSAENPath);
            System.out.println("加密结束！已将加密后文本输出到指定路径");
        }
        System.out.print("是否要进行解密？Y/N");
        String in2 = scanner.nextLine();
        if(in2.equals("Y")){
            System.out.println("解密开始！");
            //读取文件
            String text = null;
            try{
                text = ReadFileToString(RSAENPath);
            }catch (IOException msg){
                msg.printStackTrace();
            }
            //解密
            assert text != null;
            String DEText = RSADE(text,d,n,length,group);
            //解密后文本转化为明文
            RSADEText = ConvertCodeToText(DEText);
            //将明文输出到指定路径
            WriteStringToFile(RSADEText,RSADEPath);
            System.out.println("解密结束！已将解密后文本输出到指定路径");
        }
        System.out.print("是否要进行比对检验？Y/N");
        String in3 = scanner.nextLine();
        if(in3.equals("Y")){
            assert RSADEText != null;
            assert initText != null;
            if(RSADEText.equals(ConvertCodeToText(initText))){
                System.out.println("比对成功！前后文本一致");
            }
            else{
                System.out.println("比对失败！前后文本不一致");
            }
        }
    }
}