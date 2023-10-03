package com.asbe.script;

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

import static com.asbe.script.ScriptEx.OP_DECRYPT;
import static com.asbe.script.ScriptEx.OP_KEY_QUERY_NEG;

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
    public Properties pkProp = loadPropFromFile("pk.properties");
    public Properties skProp = loadPropFromFile("sk.properties");
    public Properties ctProp = loadPropFromFile("ct.properties");
    public Properties mkProp = loadPropFromFile("mk.properties");

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
    public void decryptScriptCT(AttributeSetBasedEncryption asbe, StringBuilder scriptCT, SSetCiphertext cipher, SASBEKey key) {
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
        Queue<String> dataQueue = new LinkedList<>();
        while(!scriptStack.empty()){
            String oneScript = scriptStack.pop();
            switch (oneScript){
                case "OP_KEY_QUERY_NEG":
                    String negAttrDataStr = dataQueue.poll();
                    String subNegAttrDataStr = negAttrDataStr.substring(1, negAttrDataStr.length() - 1);
                    String[] splitSubNegAttrDataStr = subNegAttrDataStr.split(":");
                    String attrSetName = splitSubNegAttrDataStr[0];
                    String attrListStr = splitSubNegAttrDataStr[1];
                    String[] attrList = attrListStr.split("|");
                    OP_KEY_QUERY_NEG(key,pairing,cipher,attrSetName,attrListStr);

                    break;
                case "OP_KEY_QUERY_PST":

                    break;
                case "OP_DEC_ATTR_NEG":

                    break;
                case "OP_DEC_ATTR_PST":

                    break;
                case "OP_OR":

                    break;
                case "OP_AND":

                    break;
                case "OP_DECRYPT":
                    String main_cipherStr = dataQueue.poll();
                    Element main_cipher = stringToElement(main_cipherStr, pairing);
                    String main_keyStr = dataQueue.poll();
                    Element main_key = stringToElement(main_keyStr, pairing);
                    String decryptDataStr = dataQueue.poll();
                    Element data = stringToElement(decryptDataStr, pairing);
                    ek = OP_DECRYPT(main_cipher, main_key, data, b, ts, tw,pairing);
                    dataQueue.add(elementToString(ek));
                    break;
                default:
                    dataQueue.add(oneScript);
                    break;
            }
        }
        if(dataQueue.size() == 1){
            String res = dataQueue.poll();
            System.out.println(res);
        }

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
        String[] strings = e.split(String.valueOf(param_separator));
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