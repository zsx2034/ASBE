package com.asbe.core;

import com.asbe.bean.CAttribute;
import com.asbe.bean.CSetAttribute;
import com.asbe.bean.Type;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Base64;

public class ScriptProcessor2 {
    private final static char separator = ' ';
    private final static char param_separator = '|';
    private final static char kv_separator = ':';
    private final static char special_variable = '%';
    public static void generateScript(SSetCiphertext ct, AttributeSetBasedEncryption asbe, BufferedWriter out) throws IOException {
        _generateScript(ct.m_policy.get(0), ct, asbe, out);

        out.append(elementToString(ct.m_main)).append(separator);
        out.append("OP_DECRYPT");
    }

    public static void _generateScript(SCiphertext.CTree node, SSetCiphertext ct, AttributeSetBasedEncryption asbe, BufferedWriter out) throws IOException {
        if (node.isLeaf()) {
            int C_No = node.m_cno;

            int AS_ID = ct.m_Ano[C_No];
            CSetAttribute attributeSet = (CSetAttribute) asbe.m_pk.m_set.m_attrList.get(AS_ID);
            String extension = "";

            Type type = ct.m_attr.get(C_No).m_type;
            switch (type) {
                case ALL, INCLUDE -> extension = "PST";
                case EXCLUDE -> extension = "NEG";
            }

            StringBuilder setInfo = new StringBuilder();
            setInfo.append("[");
            switch (type) {
                case ALL:
                    setInfo.append(attributeSet.m_attrname).append(kv_separator);
                    setInfo.append(special_variable).append("ALLSET").append(special_variable);
                    break;
                case INCLUDE:
                case EXCLUDE:
                    setInfo.append(attributeSet.m_attrname).append(kv_separator);
                    for (int i = 0; i < attributeSet.m_set.size(); i++) {
                        if (ct.m_attr.get(C_No).subset[i]) {
                            setInfo.append(attributeSet.m_set.get(i).m_Aset).append(param_separator);
                        }
                    }
                    break;
                default:
            }

            if (setInfo.charAt(setInfo.length() - 1) == param_separator) {
                setInfo.deleteCharAt(setInfo.length() - 1);
            }
            setInfo.append("]");

            out.append(setInfo).append(separator);

            out.append("OP_KEY_QUERY_").append(extension).append(separator);

            out.append(elementToString(ct.m_attr.get(C_No).c1)).append(separator);
            out.append(elementToString(ct.m_attr.get(C_No).c2)).append(separator);

            out.append("OP_DEC_ATTR_").append(extension).append(separator);

            return;
        } else if (node.isLogicAnd()) {
            int i = 0;
            while (node.m_child.get(i) != null) {
                _generateScript(node.m_child.get(i), ct, asbe, out);
                i++;
            }
            out.append("OP_AND").append(separator);
            return;
        } else if (node.isLogicOr()) {
            int i = 0;
            while (node.m_child.get(i) != null) {
                _generateScript(node.m_child.get(i), ct, asbe, out);
                i++;
            }
            out.append("OP_OR").append(separator);
            return;
        }

        System.err.println("Error while generate script for policy tree. Unknown node type.");
        System.exit(-1);
    }

    public static String subsetToString(Boolean[] st) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < st.length; i++) {
            if (st[i]) {
                s.append("1");
            } else {
                s.append("0");
            }
        }
        return s.toString();
    }

    public static boolean[] stringToSubset(String s) {
        boolean[] st = new boolean[s.length()];
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '1') {
                st[i] = true;
            } else {
                st[i] = false;
            }
        }
        return st;
    }


    public static String elementToString(Element e) {
        if (e == null) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        out.append(Base64.getEncoder().encodeToString(e.toBytes()));
        out.append(param_separator);
        if (e instanceof CurveElement) {
            out.append("G1");
        } else if (e instanceof GTFiniteElement) {
            out.append("GT");
        } else if (e instanceof ZrElement) {
            out.append("Zr");
        } else {
            System.err.println("Error while transfer element to string. Unknown element type.");
            System.exit(-1);
        }
        out.insert(0, "[");
        out.append("]");
        return out.toString();
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
}