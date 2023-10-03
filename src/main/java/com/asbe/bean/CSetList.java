package com.asbe.bean;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class CSetList {

	public int m_size;
	public List<CElementOfSet> m_attributeList;
	public List<Element> m_gList;
	
	public CSetList(){
		
		m_attributeList = new ArrayList<CElementOfSet>();
		m_gList = new ArrayList<Element>();
	}
}
