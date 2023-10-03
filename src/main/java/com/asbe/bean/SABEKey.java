package com.asbe.bean;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class SABEKey {

	public Element m_mainKey;
	public List<CSetElementKey> m_keyList;
	
	public SABEKey(){
		m_keyList = new ArrayList<CSetElementKey>();
	}
	
	public void initialMainKey(){
		
	}
	
	public void initialAttrKey(){
		
	}
	
}
