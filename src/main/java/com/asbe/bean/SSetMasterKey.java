package com.asbe.bean;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class SSetMasterKey extends MasterKey{

	public Element m_gamma;
	public Element m_g;
	
	public void initial(Pairing pairing){
		
		super.initial(pairing);
		m_gamma = pairing.getZr().newRandomElement();
	}
}
