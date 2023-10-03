package com.asbe.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;

import com.asbe.bean.CElementKey;
import com.asbe.bean.CElementOfSet;
import com.asbe.bean.CSetAttribute;
import com.asbe.bean.CSetElementKey;
import com.asbe.bean.CSetList;
import com.asbe.bean.PublicKey;
import com.asbe.bean.SABEKey;
import com.asbe.bean.SetCipher;
import com.asbe.bean.Type;

public class SSetCiphertext extends SCiphertext {

    // record info about attribute-set
    public List<SetCipher> m_attr;   //set ciphertext
    public CSetList m_gSet;
    public PublicKey m_pk;

    public SSetCiphertext() {

        m_gSet = new CSetList();
        m_attr = new ArrayList<SetCipher>();

    }

    public Element aggregateSubset1(Boolean[] st, Pairing pairing) {
        // st is the copy of subset and
        List<Element> set = new ArrayList<Element>();

        Element e1 = pairing.getZr().newElement();
        e1.setToOne();
        set.add(e1);

        for (int i = 1; i < m_gSet.m_size + 1; i++) {
            Element tmp = pairing.getZr().newElement();
            tmp.setToZero();
            set.add(i, tmp);
        }

        Element t, t1, t2;
        t = pairing.getZr().newElement();
        t1 = pairing.getZr().newElement();
        t2 = pairing.getZr().newElement();

        int count = 0;
        for (int i = 0; i < m_gSet.m_size; i++) {
            if (!st[i])
                continue;
            count++;
            CElementOfSet e = m_gSet.m_attributeList.get(i);
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

            Element pe = m_gSet.m_gList.get(i);
            tt = pe.duplicate().powZn(set.get(i));
            sum.add(tt);
        }

        Element ret;
        ret = pairing.getG1().newElement();
        ret.set(sum);

        return ret;
    }

    public Element aggregateSubset2(Boolean[] st, Pairing pairing) {

        List<Element> set = new ArrayList<Element>();
        List<Integer> index = new ArrayList<Integer>();

        int count = 0;

        for (int i = 0; i < m_gSet.m_size; i++) {

            if (!st[i]) continue;

            CElementOfSet e = m_gSet.m_attributeList.get(i);
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
                CElementOfSet e = m_gSet.m_attributeList.get(index.get(j - 1));
                Element pe1 = e.m_Ahash;
                e = m_gSet.m_attributeList.get(index.get(j - 1 + i + 1));
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

    public void encryptAttr(PublicKey pk, Pairing pairing) {

        List<CElementOfSet> pp;

        for (int i = 0; i < m_count; i++) {

            SSetPublicKey spk = (SSetPublicKey) pk;
            CSetAttribute ps = (CSetAttribute) spk.m_set.m_attrList.get(m_Ano[i]);
            pp = ps.m_set;

            m_gSet.m_attributeList = pp;
            m_gSet.m_size = pp.size();
            m_gSet.m_gList = spk.m_AF;

            Element p = m_w.get(i);
            encryptSetAttr(p, pk.m_h, i, pairing);
        }
    }

    public void decryptAttr(SABEKey key, Pairing pairing) {
        for (int i = 0; i < m_count; i++) {
            SetCipher cph = m_attr.get(i);
            // find a valid attribute in private key
            SearchRet ret = searchSetMatch(key, cph, i);
            Element ek = pairing.getGT().newElement();
            int r = ret.r;
            int rr = ret.ridx;

            if (r != -1) {
                // get info of the attribute-set in public key
                // this attribute-set is the same as the one of user's private key
                SSetPublicKey spk = (SSetPublicKey) m_pk;
                CSetAttribute ps = (CSetAttribute) spk.m_set.m_attrList.get(m_Ano[i]);
                m_gSet.m_attributeList = ps.m_set;
                m_gSet.m_size = m_gSet.m_attributeList.size();
                m_gSet.m_gList = spk.m_AF;

                // the same attribute-set in private key
                CSetElementKey eek = key.m_keyList.get(r);
                // the same attribute in private key
                CElementKey eeek = eek.m_valueList.get(rr);

                // restore ek
                decryptSetMatch(eeek, ek, cph, pairing);

                m_result.set(i, ek);
                m_flag[i] = 1;

                System.out.println("Find the match:cipher " + i + " and key " + r + " " + eek.m_strID + "-" + rr + " " + eeek.m_strID);
            } else
                m_flag[i] = 0;
        }

        for (Element o : m_result) {
            System.out.println(o);
        }

    }


    public void encryptSetAttr(Element w, Element h, int idx, Pairing pairing) {

        SetCipher cph = m_attr.get(idx);

        switch (cph.m_type) {
            case ALL: {

                cph.c1 = pairing.getG1().newElement();
                cph.c2 = pairing.getG2().newElement();

                Element p = m_gSet.m_gList.get(0);
                cph.c1.set(p.duplicate().powZn(w));
                cph.c2.set(h.duplicate().powZn(w));

            }
            break;

            case INCLUDE: {

                cph.c1 = pairing.getG1().newElement();
                cph.c2 = pairing.getG2().newElement();

                Element t = aggregateSubset2(cph.subset, pairing);
                cph.c1.set(t.duplicate().powZn(w));
                cph.c2.set(h.duplicate().powZn(w));

            }
            break;

            case EXCLUDE: {

                cph.c1 = pairing.getG1().newElement();
                cph.c2 = pairing.getG2().newElement();

                Element t = aggregateSubset1(cph.subset, pairing);
                cph.c1.set(t.duplicate().powZn(w));
                cph.c2.set(h.duplicate().powZn(w));
            }
            break;
        }
    }

    //调用该函数前需对ek初始化
    public int decryptSetMatch(CElementKey sk, Element ek, SetCipher cph, Pairing pairing) {

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
                Boolean[] st = new Boolean[m_gSet.m_size];

                if (cph.subset[sk.m_Aindex]) {

                    for (int i = 0; i < m_gSet.m_size; i++) {

                        st[i] = cph.subset[i];
                    }

                    st[sk.m_Aindex] = false;
                    t = aggregateSubset1(st, pairing);
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
                Boolean[] st = new Boolean[m_gSet.m_size];

                if (!cph.subset[sk.m_Aindex]) {

                    for (int i = 0; i < m_gSet.m_size; i++) {

                        st[i] = cph.subset[i];
                    }

                    st[sk.m_Aindex] = true;

                    t = aggregateSubset2(st, pairing);
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

    public SearchRet searchSetMatch(SABEKey key, SetCipher cph, int idx) {
        // transfer ciphertext No to attribute-set No
        // idx is the No of ciphertext
        // i is the No of attribute-set
        int i = m_Ano[idx];
        int ridx = -1;
        SearchRet ret = new SearchRet();

        for (int ii = 0; ii < key.m_keyList.size(); ii++) {
            // search the attribute-set in the private key
            CSetElementKey ppk = key.m_keyList.get(ii);
            int p = ppk.m_index;

            if (i == p) {
                // if user has the target attribute belong to the attribute-set
                // return the index of the attribute in the private key
                for (int jj = 0; jj < ppk.m_valueList.size(); jj++) {

                    CElementKey eeek = ppk.m_valueList.get(jj);

                    if (cph.m_type == Type.ALL) {

                        ridx = jj;
                        break;
                    } else if (cph.m_type == Type.INCLUDE && cph.subset[eeek.m_Aindex]) {

                        ridx = jj;
                        break;
                    } else if (cph.m_type == Type.EXCLUDE && (!cph.subset[eeek.m_Aindex])) {

                        ridx = jj;
                        break;
                    }
                }

                // find a valid attribute in the private key
                if (ridx != -1) {
                    // attribute-set index in private key
                    ret.r = ii;
                    // attribute index of the attribute-set above in private key
                    ret.ridx = ridx;
                    return ret;
                }
            }
        }

        ret.r = -1;
        ret.ridx = ridx;
        return ret;

    }
}

 