import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Author Luan
 * Desc DNS过滤文件排序，将文件内所有域名按规则进行排序
 * Date 2025/3/6 20:22
 **/
public class DNSFilter {
    /**
     * 启动类
     */
    public static void main(String[] args) {
        String filePath = "./blocklist.txt";
        // 读取文件中的域名
        Map<Character, Set<String>> filtered = readDomainsFromFile(filePath);
        // 覆盖写入原文件
        writeDomainsToFile(filePath, filtered);
        System.out.println("！！！数据完成整理！！！");
    }

    /**
     * 读取文件中的域名并返回数组
     *
     * @param filePath 文件路径
     * @return 域名数组（已过滤空行）
     */
    public static Map<Character, Set<String>> readDomainsFromFile(String filePath) {
        Map<Character, Set<String>> domainMap = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("!")) {
                    line = domain(line);
                    domainMap.computeIfAbsent(getFirstLetter(line), k -> new HashSet<>()).add(line);
                }
            }
        } catch (IOException e) {
            System.out.println("读取文件异常: " + e.getMessage());
        }
        return domainMap;
    }

    public static String domain(String line) {
        if (line.startsWith("||")) {
            line = line.substring(2);
        }
        if (line.endsWith("^")) {
            line = line.substring(0, line.length() - 1);
        }
        return line;
    }

    /**
     * 获取域名的首字母（大写形式）
     * 示例："google.com" -> 'G'
     */
    public static char getFirstLetter(String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length <= 2) {
            return Character.toUpperCase(domain.charAt(0));
        }
        return Character.toUpperCase(parts[parts.length - 2].charAt(0));
    }

    /**
     * 将域名数据写回源文件（按首字母分组排序）
     *
     * @param filePath  要写入的文件路径
     * @param domainMap 域名数据集合
     */
    public static void writeDomainsToFile(String filePath, Map<Character, Set<String>> domainMap) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // 写入文件头部
            writer.write("! Title: 黑名单\n");
            writer.write("! Description: 个人使用 Just for personal using\n");
            writer.write("! Version: " + getCurrentFormattedTime() + "\n");
            writer.write("! Homepage: https://gitee.com/luancx/dnsfilter/raw/master/blocklist.txt\n");
            writer.write("!\n");
            writer.write("!----------------------------------------------------------------------------------------------------------------------\n");
            writer.write("!\n");

            // 按字母顺序遍历
            domainMap.keySet().stream()
                    .sorted()
                    .forEach(initial -> {
                        try {
                            // 写入首字母标题
                            writer.write("# >> " + initial + " <<\n");
                            List<String> domainList = domainSetToList(domainMap.get(initial));
                            // 写入排序后的域名，首先按一级域名的首字母排序，如果首字母相同，则按域名长度排序
                            domainList.forEach(domain -> {
                                try {
                                    writer.write("||" + domain + "^\n");
                                } catch (IOException e) {
                                    System.out.println("写入文件异常: " + e.getMessage());
                                }
                            });
                            writer.write("\n");
                        } catch (IOException e) {
                            System.out.println("写入文件异常: " + e.getMessage());
                        }
                    });
        } catch (IOException e) {
            System.err.println("文件操作失败: " + e.getMessage());
        }
    }

    /**
     * 将域名Set转为List,并进行排序
     */
    private static List<String> domainSetToList(Set<String> strings) {
        return strings.stream()
                .sorted(Comparator.comparingInt(String::length).thenComparing(Comparator.naturalOrder()))
                .toList();
    }

    /**
     * 获取当前格式化的时间字符串（线程安全）
     *
     * @return 格式示例：25.03.06.2115
     */
    public static String getCurrentFormattedTime() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yy.MM.dd.HHmm"));
    }
}
