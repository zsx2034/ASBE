package com.asbe.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.IOException;
import java.net.URL;

import com.asbe.bean.CSetElementKey;
import com.asbe.bean.SSetMasterKey;

public class AttributeSetBasedEncryption extends CryptoSystemBase {

    public SSetPublicKey m_pk;
    public SSetMasterKey m_mk;
    // 0: not setup, 1: setup
    public int m_status;

    public AttributeSetBasedEncryption(boolean usePBC, String curvePath) {
        super(usePBC, curvePath);
        m_pk = new SSetPublicKey();
        m_mk = new SSetMasterKey();
        m_status = 0;
        m_mk.m_g = m_g;
    }

    public Pairing getPairing() {

        return pairing;
    }

    public void setup() {
        if (m_status == 0) {
            m_mk.initial(pairing);
            try {
                URL resource = this.getClass().getResource("/attribute-set1.txt");
                assert resource != null;
                m_pk.m_set.initial(resource.getPath());

            } catch (IOException e) {
                e.printStackTrace();
            }

            m_pk.initial(10, m_mk, m_g, m_h, pairing);
            m_status = 1;
        }
    }

    public void encrypt(SSetCiphertext cipher, Element ek) {
        // random choose a element from Zr as main key
        Element w = pairing.getZr().newRandomElement();

        cipher.m_r = pairing.getZr().newElement();
        cipher.m_main = pairing.getG2().newElement();
        cipher.m_r.set(w);

        //tree process
        System.out.println("=================tree process===============");
        cipher.genKeyTree(cipher.m_policy.get(0), w, pairing);

        for (int i = 0; i < cipher.m_count; i++) {

            Element p = cipher.m_w.get(i);
            System.out.println(p);
        }

        cipher.rebuiltKeyTree(cipher.m_policy.get(0), w, pairing);

        System.out.println("-------------------------------------------");
        System.out.println(w);

        cipher.encryptAttr(m_pk, pairing);
        cipher.m_main.set(m_pk.m_H.duplicate().powZn(w));

        ek.set(m_pk.m_R.duplicate().powZn(w));
    }

    public void genKey(SASBEKey key) {

        if (m_status == 1) {

            key.m_gSet = m_pk.m_set;

            Element t1 = pairing.getZr().newElement();
            Element t2 = pairing.getZr().newElement();
            Element tau = pairing.getZr().newRandomElement();
            key.m_mainKey = pairing.getG1().newElement();

            Element t = pairing.getZr().newElement();
            t.set(tau);

            m_mk.m_Atau.add(t);

            t1 = m_mk.m_alpha.duplicate().add(tau);
            t2 = t1.duplicate().div(m_mk.m_beta);
            key.m_mainKey = m_g.duplicate().powZn(t2);

            Element tg = pairing.getG1().newElement();
            Element tt = pairing.getZr().newElement();

            int c = key.m_keyList.size();

            tt.setToOne();
            tau.sub(tt);

            for (int i = 0; i < c; i++) {

                tg.set(m_g.duplicate().powZn(tau));
                CSetElementKey p = key.m_keyList.get(i);
                key.genSetAttrKey(p, tg, m_mk, pairing);

                key.m_keyList.set(i, p);
            }

        }

    }

    public void decrypt(SSetCiphertext cipher, SASBEKey key, Element ek) {

        Element tt = pairing.getGT().newElement();
        Element ts = pairing.getGT().newElement();
        Element tw = pairing.getGT().newElement();

        Element tg = pairing.getG1().newElement();
        Element th = pairing.getG2().newElement();
        Element test = pairing.getGT().newElement();

        Element p = m_mk.m_Atau.get(0);
        tg.set(m_g.duplicate().powZn(p));
        th.set(m_h.duplicate().powZn(cipher.m_r));
        test.set(pairing.pairing(tg, th));

        cipher.m_pk = m_pk;
        cipher.decryptAttr(key, pairing);

        //tree process
        int b = cipher.rebuiltTree(cipher.m_policy.get(0), tt, pairing);

        // verify the result
        // only for debug
        for (int j = 0; j < cipher.m_result.size(); j++) {
            p = cipher.m_w.get(j);
            th.set(m_h.duplicate().powZn(p));

            test.set(pairing.pairing(tg, th));

            System.out.println("Decryptiom test of " + j + " sharing secret1:");
            System.out.println(test);

            System.out.println("Decryptiom test of " + j + " sharing secret2:");
            p = cipher.m_result.get(j);
            System.out.println(p);
        }

        if (b != 0) {

            ts.set(pairing.pairing(key.m_mainKey, cipher.m_main));
            tw.set(ts.duplicate().div(tt));

            ek.set(tw);

        } else {

            System.out.println("Decryption Reconstruction Failure!");
            ek.setToZero();
        }
    }
}
