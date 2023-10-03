package com.asbe.core;

import com.asbe.bean.SetCipher;
import com.asbe.bean.Type;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;

import java.util.Base64;

public class ScriptProcessor {
    private final static String separator = " ";
    private final static String param_separator = "-";

    public static void generateScript(SSetCiphertext ct, AttributeSetBasedEncryption asbe) {
        // generate script for attribute decryption
        StringBuilder str_builder = new StringBuilder();
        for (int i = 0; i < ct.m_count; i++) {
            // get attribute-set id in public key
            int AS_ID = ct.m_Ano[i];
            str_builder.append(AS_ID).append(separator);

            Type type = ct.m_attr.get(i).m_type;
            // share subset
            if (type == Type.ALL) {
                int n = asbe.m_pk.m_set.m_attrList.size();
                str_builder.append("1".repeat(n));
                str_builder.append(separator);
            } else {
                Boolean[] subset = ct.m_attr.get(i).subset;
                str_builder.append(subsetToString(subset)).append(separator);
            }

            // select sk and pk for target attribute-set
            SetCipher cipher = ct.m_attr.get(i);
            str_builder.append(elementToString(cipher.c2)).append(separator);
            str_builder.append(elementToString(cipher.c1)).append(separator);
            switch (ct.m_attr.get(i).m_type) {
                // the following OP should check whether the result of query operation is null
                case ALL -> str_builder.append("ALL").append(separator);
                case INCLUDE -> str_builder.append("INCLUDE").append(separator);
                case EXCLUDE -> str_builder.append("EXCLUDE").append(separator);
                default -> {
                    System.err.println("Error while generate script, Unknown type: " + ct.m_attr.get(i).m_type);
                    System.exit(-1);
                }
            }
            str_builder.append("OP_DEC_ATTR").append(separator);
        }

        // generate script for rebuild tree
        _generateScriptForPolicy(ct.m_policy.get(0), str_builder);

        // message decrypt
        str_builder.append(elementToString(ct.m_main)).append(separator).append("OP_DECRYPT").append(separator);

        System.out.println(str_builder);
    }

    private static void _generateScriptForPolicy(SCiphertext.CTree node, StringBuilder stringBuilder) {
        if (node.isLeaf()) {
            stringBuilder.append("OP_CHECK_FLAG").append(param_separator).append(node.m_cno).append(separator);
            return ;
        }
        else if (node.isLogicAnd()) {
            int i = 0;
            while (node.m_child.get(i) != null) {
                _generateScriptForPolicy(node.m_child.get(i), stringBuilder);
                i++;
            }
            stringBuilder.append("OP_AND").append(param_separator).append(i).append(separator);
            return;
        }
        else if (node.isLogicOr()) {
            int i = 0;
            while (node.m_child.get(i) != null) {
                _generateScriptForPolicy(node.m_child.get(i), stringBuilder);
                i++;
            }
            stringBuilder.append("OP_OR").append(param_separator).append(i).append(separator);
            return;
        }

        System.err.println("Error while generate script for policy tree. Unknown node type.");
        System.exit(-1);
    }

    public static String subsetToString(Boolean[] st) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < st.length; i++) {
            if (st[i]) {
                s.append("0");
            } else {
                s.append("1");
            }
        }
        return s.toString();
    }

    public static boolean[] stringToSubset(String s) {
        boolean[] st = new boolean[s.length()];
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '0') {
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
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(Base64.getEncoder().encodeToString(e.toBytes()));
        stringBuilder.append(param_separator);
        if (e instanceof CurveElement) {
            stringBuilder.append("G1");
        } else if (e instanceof GTFiniteElement) {
            stringBuilder.append("GT");
        } else {
            System.err.println("Error while transfer element to string. Unknown element type.");
            System.exit(-1);
        }

        return stringBuilder.toString();
    }

    public static Element stringToElement(String e, Pairing pairing) {
        String[] strings = e.split("-");
        byte[] bytes = Base64.getDecoder().decode(strings[0]);
        if (strings[1].equals("G1")) {
            return pairing.getG1().newElementFromBytes(bytes);
        } else if (strings[1].equals("GT")) {
            return pairing.getGT().newElementFromBytes(bytes);
        } else {
            System.err.println("Error while decode string to element, Unknown element type: " + strings[1]);
            System.exit(-1);
            return null;
        }
    }


}
