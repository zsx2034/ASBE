package com.asbe.script;

import com.asbe.bean.CElementKey;
import com.asbe.core.AttributeSetBasedEncryption;
import com.asbe.core.SASBEKey;
import com.asbe.core.SSetCiphertext;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

import static com.asbe.script.ScriptEx.*;
/**
 * @Author: QuanLin Du
 * @Date: 2023-10-02-11:14
 * @Description:
 */
public class Engine {
    private final static char separator = ' ';
    private final static char param_separator = '|';
    private final static char kv_separator = ':';
    private final static char special_variable = '%';
    public Pairing pairing = PairingFactory.getPairing("a.properties");
    public Properties pkProp = loadPropFromFile("data/pk.properties");
    public Properties skProp = loadPropFromFile("data/sk.properties");
    public Properties ctProp = loadPropFromFile("data/ct.properties");
    public Properties mkProp = loadPropFromFile("data/mk.properties");

    public void decryptScript(StringBuilder scriptCT, Element ee) {
        Element tt = pairing.getGT().newElement();
        Element ts = pairing.getGT().newElement();
        Element tw = pairing.getGT().newElement();
        Element tg = pairing.getG1().newElement();
        Element th = pairing.getG2().newElement();
        Element test = pairing.getGT().newElement();
        String m_atauStr = mkProp.getProperty("m_Atau");
        Element m_atau = stringToElement(m_atauStr,pairing);
        Element p = m_atau;
        Integer b = null;
        Element ek = pairing.getGT().newElement();
        String m_gStr = mkProp.getProperty("m_g");
        Element m_g = stringToElement(m_gStr,pairing);
        String m_hStr = pkProp.getProperty("m_h");
        Element m_h = stringToElement(m_hStr,pairing);
        tg.set(m_g.duplicate().powZn(p));
        String m_rStr = ctProp.getProperty("m_r");
        Element m_r = stringToElement(m_rStr,pairing);
        th.set(m_h.duplicate().powZn(m_r));
        test.set(pairing.pairing(tg, th));
    }
    public Element decryptScriptCT(AttributeSetBasedEncryption asbe, StringBuilder scriptCT, SSetCiphertext cipher, SASBEKey key) {
        Element tt = pairing.getGT().newElement();
        Element ts = pairing.getGT().newElement();
        Element tw = pairing.getGT().newElement();
        Element tg = pairing.getG1().newElement();
        Element th = pairing.getG2().newElement();
        Element test = pairing.getGT().newElement();
        String m_atauStr = mkProp.getProperty("m_Atau");
        Element m_atau = stringToElement(m_atauStr,pairing);
        Element p = m_atau;
        Integer b = null;
        Element ek = pairing.getGT().newElement();
        String m_gStr = mkProp.getProperty("m_g");
        Element m_g = stringToElement(m_gStr,pairing);
        String m_hStr = pkProp.getProperty("m_h");
        Element m_h = stringToElement(m_hStr,pairing);
        tg.set(m_g.duplicate().powZn(p));
        th.set(m_h.duplicate().powZn(cipher.m_r));
        test.set(pairing.pairing(tg, th));
        cipher.m_pk = asbe.m_pk; //TODO

        String scriptStr = scriptCT.toString();
        String[] scriptStrList = scriptStr.split(" ");
        Stack<String> scriptStack = new Stack<>();
        for (int i = scriptStrList.length - 1 ; i >= 0 ; i --) {
            scriptStack.push(scriptStrList[i]);
        }
        Stack<Object> dataTempStack = new Stack<>();
        while(!scriptStack.empty()){
            String oneScript = scriptStack.pop();
            switch (oneScript){
                case "OP_KEY_QUERY_NEG":
                    String negAttrDataStr = (String) dataTempStack.pop();
                    String negAttrDataStrSubstring = negAttrDataStr.substring(1, negAttrDataStr.length() - 1);
                    String[] splitSubNegAttrDataStr = negAttrDataStrSubstring.split(":");
                    String attrSetNameNeg = splitSubNegAttrDataStr[0];
                    String attrListStrNeg = splitSubNegAttrDataStr[1];
                    String[] attrListNeg = attrListStrNeg.split("\\|");
                    CElementKey skNeg = OP_KEY_QUERY_NEG(key, pairing, cipher, attrSetNameNeg, attrListNeg);
                    if(skNeg == null){
                        System.out.println("解密失败！");
                        System.exit(0);
                    }
                    dataTempStack.add(skNeg);
                    break;
                case "OP_KEY_QUERY_PST":
                    String pstAttrDataStr = (String) dataTempStack.pop();
                    String pstAttrDataStrSubstring = pstAttrDataStr.substring(1, pstAttrDataStr.length() - 1);
                    String[] splitSubPstAttrDataStr = pstAttrDataStrSubstring.split(":");
                    String attrSetNamePst = splitSubPstAttrDataStr[0];
                    String attrListStrPst = splitSubPstAttrDataStr[1];
                    String[] attrListPst = attrListStrPst.split("\\|");
                    CElementKey skPst = OP_KEY_QUERY_PST(key, pairing, cipher, attrSetNamePst, attrListPst);
                    if(skPst == null){
                        System.out.println("解密失败！");
                        System.exit(0);
                    }
                    dataTempStack.add(skPst);
                    break;
                case "OP_DEC_ATTR_NEG":
                    String c2_negStr = (String) dataTempStack.pop();
                    Element c2_neg = stringToElement(c2_negStr, pairing);
                    String c1_negStr = (String) dataTempStack.pop();
                    Element c1_neg = stringToElement(c1_negStr, pairing);
                    CElementKey sk_neg = (CElementKey)dataTempStack.pop();
                    Element ek_neg = OP_DEC_ATTR_NEG(sk_neg, c1_neg, c2_neg, pairing);
                    dataTempStack.add(ek_neg);
                    break;
                case "OP_DEC_ATTR_PST":
                    String c2_pstStr = (String) dataTempStack.pop();
                    Element c2_pst = stringToElement(c2_pstStr, pairing);
                    String c1_pstStr = (String) dataTempStack.pop();
                    Element c1_pst = stringToElement(c1_pstStr, pairing);
                    CElementKey sk_pst = (CElementKey)dataTempStack.pop();
                    Element ek_pst = OP_DEC_ATTR_PST(sk_pst, c1_pst, c2_pst, pairing);
                    dataTempStack.add(ek_pst);
                    break;
                case "OP_OR":
                    Element ek_right_or = (Element) dataTempStack.pop();
                    Element ek_left_or = (Element) dataTempStack.pop();
                    Element ek_or = OP_OR(ek_left_or,ek_right_or,pairing);
                    dataTempStack.add(ek_or);
                    break;
                case "OP_AND":
                    Element ek_right_and = (Element) dataTempStack.pop();
                    Element ek_left_and = (Element) dataTempStack.pop();
                    Element ek_and = OP_AND(ek_left_and,ek_right_and,pairing);
                    dataTempStack.add(ek_and);
                    break;
                case "OP_DECRYPT":
                    String main_cipherStr = (String) dataTempStack.pop();
                    Element main_cipher = stringToElement(main_cipherStr, pairing);
                    Element data = (Element) dataTempStack.pop();
                    Element main_key = key.m_mainKey;
                    ek = OP_DECRYPT(main_cipher, main_key, data,ts, tw,pairing);
                    dataTempStack.add(elementToString(ek));
                    break;
                default:
                    dataTempStack.add(oneScript);
                    break;
            }
        }
        if(dataTempStack.size() == 1){
            String res = (String) dataTempStack.pop();
            System.out.println(res);
            Element element = stringToElement(res,pairing);
            return element;
        }
        return null;
    }


    public static String elementToString(Element e) {
        if (e == null) {
            return null;
        }
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(Base64.getEncoder().encodeToString(e.toBytes()));
        stringBuilder.append(param_separator);
        if (e instanceof CurveElement) {
            stringBuilder.append("G1");
        } else if (e instanceof GTFiniteElement) {
            stringBuilder.append("GT");
        } else if (e instanceof ZrElement) {
            stringBuilder.append("Zr");
        } else {
            System.err.println("Error while transfer element to string. Unknown element type.");
            System.exit(-1);
        }
        stringBuilder.insert(0, "[");
        stringBuilder.append("]");
        return stringBuilder.toString();
    }

    public static Element stringToElement(String e, Pairing pairing) {
        String ee = e.substring(1, e.length() - 1);
        String[] strings = ee.split("\\|");
        byte[] bytes = Base64.getDecoder().decode(strings[0]);
        switch (strings[1]) {
            case "G1" -> {
                return pairing.getG1().newElementFromBytes(bytes);
            }
            case "GT" -> {
                return pairing.getGT().newElementFromBytes(bytes);
            }
            case "Zr" -> {
                return pairing.getZr().newElementFromBytes(bytes);
            }
            default -> {
                System.err.println("Error while decode string to element, Unknown element type: " + strings[1]);
                System.exit(-1);
                return null;
            }
        }
    }
    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }


}
