package com.asbe.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import com.asbe.jdbc.AbstractJPBC;

public class CryptoSystemBase extends AbstractJPBC{

	// m_g equals m_h
	// m_g is a generator of G1
	// m_h is a generator of G2
	Element m_g, m_h;
	
	public CryptoSystemBase(boolean usePBC, String curvePath) {
		
		super(usePBC, curvePath);
		
		pairing = PairingFactory.getPairing(curvePath);
		
		m_g = pairing.getG1().newRandomElement();
		m_h = pairing.getG2().newRandomElement();
		
		m_g.set(m_h);
	}
	
	
}
