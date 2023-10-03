package com.asbe.bean;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class PublicKey {

	public Element m_H;
	public Element m_h;
	public Element m_R;

	public void initial(MasterKey mk, Element m_h, Element m_g, Pairing pairing){
		
		this.m_h = pairing.getG2().newElement();
		this.m_H = pairing.getG2().newElement();
		this.m_R = pairing.getGT().newElement();
		
		Element G;
		G = pairing.getG1().newElement();
		this.m_h = m_h;
		m_H = m_h.duplicate().powZn(mk.m_beta);
		G = m_g.duplicate().powZn(mk.m_alpha);
		m_R = pairing.pairing(G, m_h);
	}
}
