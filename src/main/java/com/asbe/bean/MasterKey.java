package com.asbe.bean;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;

public class MasterKey {

	public Element m_alpha;
	public Element m_beta;
	public List<Element> m_Atau;
	
	public void initial(Pairing pairing){
		
		m_alpha = pairing.getZr().newRandomElement();
		m_beta = pairing.getZr().newRandomElement();
		m_Atau = new ArrayList<Element>();
	}
}
