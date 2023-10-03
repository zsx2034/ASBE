package com.asbe.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import com.asbe.bean.CElementKey;
import com.asbe.bean.CElementOfSet;
import com.asbe.bean.CSetAttribute;
import com.asbe.bean.CSetElementKey;
import com.asbe.bean.SABEKey;
import com.asbe.bean.SSetMasterKey;

public class SASBEKey extends SABEKey{

	public SSetAttributeList m_gSet;
	
	public void genSetAttrKey(CSetElementKey key, Element tg, SSetMasterKey mk, Pairing pairing){
		
		int c = key.m_valueList.size();
		
		for(int i=0; i<c; i++){
			
			CElementKey p = key.m_valueList.get(i);
			genElementKey(key.m_index, p, mk, pairing);
			p.m_sk.set(tg.duplicate().mul(p.m_sk));
			
			key.m_valueList.set(i, p);
		}
	}
	
	public int genElementKey(int index, CElementKey sk, SSetMasterKey mk, Pairing pairing){
		
		Element t1 = pairing.getZr().newElement();
		
		if(index<m_gSet.m_attrList.size()){
			
			CSetAttribute ps = (CSetAttribute) m_gSet.m_attrList.get(index);
			CElementOfSet pe = ps.m_set.get(sk.m_Aindex);
			
			Element pe1 = pe.m_Ahash;
			Element pe2 = pe.m_AH;
			
			t1.set(mk.m_gamma.duplicate().add(pe1));
			t1.set(pe1.duplicate().div(t1));
			
			sk.m_sk = pairing.getG1().newElement();
			sk.m_sk.set(mk.m_g.duplicate().powZn(t1));
			
			sk.m_Hi = pairing.getG2().newElement();
			sk.m_Hi.set(pe2);
			
			return 1;
		}else{
			
			System.out.println("Key Generation Error!");
			return 0;
		}
	}
}
