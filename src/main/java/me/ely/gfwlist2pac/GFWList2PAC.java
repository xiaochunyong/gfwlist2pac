package me.ely.gfwlist2pac;

import com.alibaba.fastjson.JSON;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import org.bouncycastle.util.encoders.Base64;
import java.util.*;

/**
 * Created by ely on 15/12/2016.
 */
public class GFWList2PAC {

    private static final Logger logger = LoggerFactory.getLogger(GFWList2PAC.class);

    public static String GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt";

    public static void update(Map<String, String> argsMap) throws IOException {
        String input = argsMap.get("input");
        String output = argsMap.get("output");
        String proxy = argsMap.get("proxy");
        String userRule = argsMap.get("user-rule");

        String content = "";
        if (input.length() > 0) {
            if (input.startsWith("http")) {
                logger.info("Downloading gfwlist from {}", input);
                content = fetchGFWList(input);
            } else {
                logger.info("read local gfwlist file from {}", input);
                InputStream in = new FileInputStream(input);
                content = readStream(in);
                // TODO invoke in.close();
            }
        } else {
            logger.info("Downloading gfwlist from {}", GFWLIST_URL);
            content = fetchGFWList(GFWLIST_URL);
        }

        String userRuleContent = "";
        if (userRule.length() > 0) {
            if (userRule.startsWith("http")) {
                logger.info("Downloading user rule from {}", userRule);
                userRuleContent = fetchGFWList(userRule);
            } else {
                logger.info("read local user rule file from {}", userRule);
                InputStream in = new FileInputStream(userRule);
                userRuleContent = readStream(in);
            }
        }

        content = decodeGFWList(content);

        Set<String> domains = parseGFWList(content, userRuleContent);

        domains = reduceDomains(domains);

        String pacContent = generatePAC(domains, proxy);

        FileWriter fw = new FileWriter(new File(output));
        fw.write(pacContent);
        fw.flush();
        fw.close();
    }

    public static String decodeGFWList(String gfwlist) {
        if (gfwlist.contains(".")) {
            return gfwlist;
        } else {
            return new String(Base64.decode(gfwlist));
        }
    }

    public static String getHostname(String uri) {
        if (!uri.startsWith("http:")) {
            uri = "http://" + uri;
        }
        try {
            return new URL(uri).getHost();
        } catch (MalformedURLException e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

    public static void addDomainToSet(Set<String> domains, String uri) {
        String hostname = getHostname(uri);
        if (hostname != null) {
            if (hostname.startsWith(".")) {
                hostname = hostname.substring(1);
            }
            if (hostname.endsWith("/")) {
                hostname = hostname.substring(0, hostname.length() - 1);
            }
            if (hostname.length() > 0) {
                domains.add(hostname);
            }
        }
    }


    public static Set<String> parseGFWList(String content, String userRule) {
        List<String> gfwlist = new ArrayList<>();
        gfwlist.addAll(Arrays.asList(content.split("\n")));
        gfwlist.addAll(Arrays.asList(userRule.split("\n")));

        Set<String> domains = new HashSet<>();
        domains.addAll(Arrays.asList(readStream(GFWList2PAC.class.getResourceAsStream("/builtin.txt")).split("\n")));

        for (String line : gfwlist) {
            if (line.contains(".*")) {
                continue;
            } else if (line.contains("*")) {
                line = line.replace("*", "/");
            }

            if (line.startsWith("!")) {
                continue;
            } else if (line.startsWith("[")) {
                continue;
            } else if (line.startsWith("@")) {
                // ignore white list
                continue;
            } else if (line.startsWith("||")) {
                addDomainToSet(domains, line.substring(2));
            } else if (line.startsWith("|")) {
                addDomainToSet(domains, line.substring(1));
            } else if (line.startsWith(".")) {
                addDomainToSet(domains, line.substring(1));
            } else {
                addDomainToSet(domains, line);
            }
        }
        return domains;
    }

    public static Set<String> reduceDomains(Set<String> domains) {
        // reduce 'www.google.com' to 'google.com'
        // remove invalid domains
        Set<String> tlds = new HashSet<>();
        tlds.addAll(Arrays.asList(readStream(GFWList2PAC.class.getResourceAsStream("/tld.txt")).split("\n")));

        Set<String> newDomains = new HashSet<>();
        for (String domain : domains) {
            String[] domainParts = domain.split("\\.");
            String lastRootDomain = null;
            for (int i = 0; i < domainParts.length; i++) {
                String rootDomain = String.join(".", Arrays.copyOfRange(domainParts, domainParts.length - i - 1, domainParts.length));
                if (i == 0) {
                    if (!tlds.contains(rootDomain)) {
                        // root_domain is not a valid tld
                        break;
                    }
                }
                lastRootDomain = rootDomain;
                if (tlds.contains(rootDomain)) {
                    continue;
                } else {
                    break;
                }
            }

            if (lastRootDomain != null) {
                newDomains.add(lastRootDomain);
            }
        }
        return newDomains;
    }

    public static String generatePAC(Set<String> domains, String proxy) {
        logger.info("generating pac file...");
        String pacContent = readStream(GFWList2PAC.class.getResourceAsStream("/proxy.pac"));
        Map<String, Integer> domainMap = new HashMap<>();
        for (String domain : domains) {
            domainMap.put(domain, 1);
        }
        pacContent = pacContent.replace("__PROXY__", JSON.toJSONString(proxy, true));
        pacContent = pacContent.replace("__DOMAINS__", JSON.toJSONString(domainMap, true));

        return pacContent;
    }

    public static String readStream(InputStream in) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            StringBuilder sb = new StringBuilder();
            String line = null;
            while ((line = reader.readLine()) != null) {
                sb.append(line + "\n");
            }
            return sb.toString();
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
        return "";
    }

    public static String fetchGFWList(String uri) throws IOException {
        try {
            URL url = new URL(uri);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            InputStream in = con.getInputStream();

            String data = readStream(in);

            in.close();
            con.disconnect();
            return data;
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
        return "";
    }

    public static Map<String, String> parseArgs(String[] args) {
        Options options = new Options();
        options.addOption(Option.builder("i").longOpt("input").argName("local gfwlist file").hasArg().desc("path to gfwlist").build());
        options.addOption(Option.builder("o").longOpt("output").argName("output").required().hasArg().desc("path to output pac").build());
        options.addOption(Option.builder("p").longOpt("proxy").argName("proxy").required().hasArg().desc("the proxy parameter in the pac file, for example: SOCKS5 127.0.0.1:1080;").build());
        options.addOption(Option.builder().longOpt("user-rule").argName("local gfwlist file").hasArg().desc("user rule file, which will be appended to gfwlist").build());
        options.addOption(Option.builder("h").longOpt("help").build());


        Map<String, String> argsMap = new HashMap<>();
        try {
            CommandLineParser parser = new DefaultParser();
            CommandLine cl = parser.parse(options, args);
            if (cl.hasOption("h")) {
                throw new ParseException("print help");
            }
            argsMap.put("input", cl.getOptionValue("i", ""));
            argsMap.put("output", cl.getOptionValue("o"));
            argsMap.put("proxy", cl.getOptionValue("p"));
            argsMap.put("user-rule", cl.getOptionValue("user-rule", ""));
            return argsMap;
        } catch (ParseException e) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp( "java GFWList2PAC -o <proxy.pac> -p 'SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT;'", options);
        }

        return null;
    }

    public static void main(String[] args) throws IOException {
//        args = new String[]{
//            "-i",
//            "gfwlist.txt",
//            "-o",
//            "proxy.pac",
//            "-p",
//            "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT;",
//            "--user-rule",
//            "userfule.txt"
//        };
        Map<String, String> argsMap = parseArgs(args);
        if (argsMap != null) {
            update(argsMap);
        }
    }

}