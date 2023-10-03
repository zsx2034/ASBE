package com.asbe.script;

import com.asbe.bean.*;
import com.asbe.core.*;
import com.asbe.core.SCiphertext.CTree;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author: QuanLin Du
 * @Date: 2023-09-27-14:21
 * @Description:
 */
public class ScriptEx {

    public static SetCipher tempCph = null;
    public static int tempNodeIndex = -1;
    public static SSetCiphertext tempCipher = null;

    public static CElementKey OP_KEY_QUERY_NEG(SABEKey key, Pairing pairing, SSetCiphertext cipher, String attrSetName, String[] attrList){
        if(tempCipher == null)
            tempCipher = cipher;
        return OP_KEY_QUERY_NEG_MAIN(cipher,key, pairing,attrSetName,attrList);
    }
    public static CElementKey OP_KEY_QUERY_PST(SASBEKey key, Pairing pairing, SSetCiphertext cipher, String attrSetNamePst, String[] attrListPst) {
        if(tempCipher == null)
            tempCipher = cipher;
        return OP_KEY_QUERY_NEG_MAIN(cipher,key, pairing,attrSetNamePst,attrListPst);
    }
    public static Element OP_DEC_ATTR_NEG(CElementKey sk_neg, Element c1_neg, Element c2_neg, Pairing pairing) {
        Element ek = pairing.getGT().newElement();
        return getEk(sk_neg, pairing, ek);
    }
    public static Element OP_DEC_ATTR_PST(CElementKey sk_neg, Element c1_neg, Element c2_neg, Pairing pairing) {
        Element ek = pairing.getGT().newElement();
        return getEk(sk_neg, pairing, ek);
    }

    private static Element getEk(CElementKey sk_neg, Pairing pairing, Element ek) {
        decryptSetMatch(sk_neg, ek, tempCph, pairing,tempCipher);
        tempCipher.m_result.set(tempNodeIndex, ek);
        tempCipher.m_flag[tempNodeIndex] = 1;
        return ek;
    }

    public static CElementKey OP_KEY_QUERY_NEG_MAIN(SSetCiphertext ciphertext, SABEKey key, Pairing pairing, String attrSetName, String[] attrList) {
            int i = 0;
            while(attrList[0].equals(ciphertext.m_attr.get(i).ElementsOfSet.get(0))) i ++;
            tempNodeIndex = i;
            SetCipher cph = ciphertext.m_attr.get(i);
            tempCph = cph;
            // find a valid attribute in private key
            SearchRet ret = ciphertext.searchSetMatch(key, cph, i);
            Element ek = pairing.getGT().newElement();
            int r = ret.r;
            int rr = ret.ridx;

            if (r != -1) {
                // get info of the attribute-set in public key
                // this attribute-set is the same as the one of user's private key
                SSetPublicKey spk = (SSetPublicKey) ciphertext.m_pk;
                CSetAttribute ps = (CSetAttribute) spk.m_set.m_attrList.get(ciphertext.m_Ano[i]);
                ciphertext.m_gSet.m_attributeList = ps.m_set;
                ciphertext.m_gSet.m_size = ciphertext.m_gSet.m_attributeList.size();
                ciphertext.m_gSet.m_gList = spk.m_AF;

                // the same attribute-set in private key
                CSetElementKey eek = key.m_keyList.get(r);
                // the same attribute in private key
                CElementKey eeek = eek.m_valueList.get(rr);
                return eeek;
            }

        return null;
    }

    public static Element OP_OR(Element ek_left_or, Element ek_right_or, Pairing pairing) {
        Element sum = pairing.getGT().newElement();
        sum.setToOne();
        sum.mul(ek_left_or);
        return sum;
    }

    public static Element OP_AND(Element ek_left_and, Element ek_right_and,Pairing pairing) {
        Element sum = pairing.getGT().newElement();
        sum.setToOne();
        sum.mul(ek_left_and);
        sum.mul(ek_right_and);
        return sum;
    }
    public static Element OP_DECRYPT(Element main_cipher, Element main_key, Element data, Element ts, Element tw, Pairing pairing) {
        Element ek = pairing.getGT().newElement();
        ts.set(pairing.pairing(main_key, main_cipher));
        tw.set(ts.duplicate().div(data));
        ek.set(tw);
        return ek;
    }
    //调用该函数前需对ek初始化
    public static int decryptSetMatch(CElementKey sk, Element ek, SetCipher cph, Pairing pairing, SSetCiphertext cipher) {

        int state = 1;

        switch (cph.m_type) {

            case ALL: {
                Element t1 = pairing.getGT().newElement();
                Element t2 = pairing.getGT().newElement();
                t1.set(pairing.pairing(sk.m_sk, cph.c2));
                t2.set(pairing.pairing(cph.c1, sk.m_Hi));
                ek.set(t1.duplicate().mul(t2));
            }
            break;

            case INCLUDE: {

                Element t1 = pairing.getGT().newElement();
                Element t2 = pairing.getGT().newElement();

                t1.set(pairing.pairing(sk.m_sk, cph.c2));

                Element t;
                Boolean[] st = new Boolean[cipher.m_gSet.m_size];

                if (cph.subset[sk.m_Aindex]) {

                    for (int i = 0; i < cipher.m_gSet.m_size; i++) {

                        st[i] = cph.subset[i];
                    }

                    st[sk.m_Aindex] = false;
                    t = aggregateSubset1(st, pairing,cipher);
                    t2.set(pairing.pairing(t, cph.c1));

                    ek.set(t1.duplicate().mul(t2));
                } else {

                    System.out.println("ERROR!");
                    ek.setToZero();
                    state = 0;
                }
            }
            break;

            case EXCLUDE: {

                Element t1 = pairing.getGT().newElement();
                Element t2 = pairing.getGT().newElement();

                t1.set(pairing.pairing(sk.m_sk, cph.c2));

                Element t;
                Boolean[] st = new Boolean[cipher.m_gSet.m_size];

                if (!cph.subset[sk.m_Aindex]) {

                    for (int i = 0; i < cipher.m_gSet.m_size; i++) {

                        st[i] = cph.subset[i];
                    }

                    st[sk.m_Aindex] = true;

                    t = aggregateSubset2(st, pairing,cipher);
                    t2.set(pairing.pairing(t, cph.c1));

                    ek.set(t1.duplicate().mul(t2));

                } else {

                    System.out.println("ERROR!");
                    ek.setToZero();
                    state = 0;
                }
            }
            break;
        }
        return state;
    }
    //public static SCiphertext P_DEC_ATTR_PST();
    public static Element aggregateSubset1(Boolean[] st, Pairing pairing, SSetCiphertext cipher) {
        // st is the copy of subset and
        List<Element> set = new ArrayList<Element>();

        Element e1 = pairing.getZr().newElement();
        e1.setToOne();
        set.add(e1);

        for (int i = 1; i < cipher.m_gSet.m_size + 1; i++) {
            Element tmp = pairing.getZr().newElement();
            tmp.setToZero();
            set.add(i, tmp);
        }

        Element t, t1, t2;
        t = pairing.getZr().newElement();
        t1 = pairing.getZr().newElement();
        t2 = pairing.getZr().newElement();

        int count = 0;
        for (int i = 0; i < cipher.m_gSet.m_size; i++) {
            if (!st[i])
                continue;
            count++;
            CElementOfSet e = cipher.m_gSet.m_attributeList.get(i);
            Element pe = e.m_Ahash;
            t.set(set.get(0));
            t1.set(t.duplicate().mul(pe).duplicate());
            set.set(0, t1.duplicate());

            int count1 = 0;
            for (Element o : set) {
                System.out.print("第" + count1 + ":");
                System.out.println(o);
                count1++;
            }

            System.out.println("============aggre1:tail==============" + count);
            System.out.println(t);
            System.out.println(pe);
            System.out.println(t1);

            for (int j = 1; j <= i; j++) {
                t2.set(set.get(j));
                t1.set(t2.duplicate().mul(pe));
                t1.add(t);
                set.set(j, t1.duplicate());
                t.set(t2);

                System.out.println("==========aggr1=" + i + "===" + j);
                System.out.println(t1);
                System.out.println(t2);
                System.out.println(t);

                System.out.println("================================");
            }

            set.set(i + 1, t.duplicate());

            System.out.println("=========aggre1:head===" + count + "========");
            System.out.println(t);
            System.out.println("================================");
        }

        Element sum, tt;
        sum = pairing.getG1().newElement();
        tt = pairing.getG1().newElement();
        sum.setToZero();


        for (int i = 0; i <= count; i++) {

            Element pe = cipher.m_gSet.m_gList.get(i);
            tt = pe.duplicate().powZn(set.get(i));
            sum.add(tt);
        }

        Element ret;
        ret = pairing.getG1().newElement();
        ret.set(sum);

        return ret;
    }

    public static Element aggregateSubset2(Boolean[] st, Pairing pairing, SSetCiphertext cipher) {

        List<Element> set = new ArrayList<Element>();
        List<Integer> index = new ArrayList<Integer>();

        int count = 0;

        for (int i = 0; i < cipher.m_gSet.m_size; i++) {

            if (!st[i]) continue;

            CElementOfSet e = cipher.m_gSet.m_attributeList.get(i);
            Element pe = e.m_AH;

            set.add(pe);
            index.add(i);
            count++;
        }

        if (count == 0) {

            System.out.println("EXCLUDE cannot process count = 0.");
            return null;
        }

        Element t, t1;
        t = pairing.getZr().newElement();
        t1 = pairing.getG2().newElement();

        for (int i = 0; i < count - 1; i++) {
            for (int j = 1; j < count - i; j++) {

                t1 = set.get(j).duplicate().sub(set.get(j - 1));
                CElementOfSet e = cipher.m_gSet.m_attributeList.get(index.get(j - 1));
                Element pe1 = e.m_Ahash;
                e = cipher.m_gSet.m_attributeList.get(index.get(j - 1 + i + 1));
                Element pe2 = e.m_Ahash;

                t = pe1.duplicate().sub(pe2);
                t.invert();
                set.get(j - 1).set(t1.duplicate().powZn(t).duplicate());

            }
        }

        Element ret;
        ret = pairing.getG2().newElement();
        ret.set(set.get(0));

        return ret;
    }
}
