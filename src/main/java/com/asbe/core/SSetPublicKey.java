package com.asbe.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;

import com.asbe.bean.CElementOfSet;
import com.asbe.bean.CSetAttribute;
import com.asbe.bean.PublicKey;
import com.asbe.bean.SSetMasterKey;

public class SSetPublicKey extends PublicKey {

    public SSetAttributeList m_set;
    public List<Element> m_AF;

    public SSetPublicKey() {
        m_set = new SSetAttributeList();
        m_AF = new ArrayList<Element>();
    }

    public void initial(int m, SSetMasterKey mk, Element m_g, Element m_h, Pairing pairing) {

        this.initial(mk, m_h, m_g, pairing);
        Element tt;
        tt = pairing.getZr().newOneElement();

        for (int i = 0; i < m; i++) {

            Element t = pairing.getG1().newElement();
            tt.mul(mk.m_gamma);
            t.set(m_g.duplicate().powZn(tt));
            m_AF.add(t);
        }

        for (int i = 0; i < m_set.m_attrList.size(); i++) {

            CSetAttribute pa = (CSetAttribute) m_set.m_attrList.get(i);

            int n = pa.m_set.size();
            System.out.println("Attribute " + i + " : " + pa.m_attrname);

            for (int j = 0; j < n; j++) {

                Element pe = pairing.getG2().newElement();
                Element t = pairing.getZr().newElement();

                CElementOfSet e = pa.m_set.get(j);
                String str = e.m_Aset;
                System.out.println("value " + j + " : " + str);

                t.setFromHash(str.getBytes(), 0, str.getBytes().length);

                e.m_Ahash = pairing.getZr().newElement();
                e.m_Ahash.set(t);

                t.add(mk.m_gamma);
                tt.set(t.duplicate().invert());
                pe.set(m_h.duplicate().powZn(tt));

                e.m_AH = pairing.getG2().newElement();
                e.m_AH.set(pe);
            }
        }

    }
}
