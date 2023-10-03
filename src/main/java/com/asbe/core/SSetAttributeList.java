package com.asbe.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import com.asbe.bean.CElementOfSet;
import com.asbe.bean.CSetAttribute;
import com.asbe.bean.SAttributeList;

public class SSetAttributeList extends SAttributeList{

	public void initial(String path) throws IOException{
		
		int count = 0;

		File f = new File(path);
		 
		 BufferedReader br=new BufferedReader(new FileReader(f));
		 String temp;
		 
		 //读取第一行 - AttrbuteNUmber
		 temp=br.readLine();
		 String[] message1 = temp.split(":");
		 if(message1[0].equals("Attribute Number")){
			 count = Integer.parseInt(message1[1]);
			 System.out.println("count= "+ count);
		 }
		 
		int n = 0;
		String str;
		
		for(int i=0; i<count; i++){
			
			temp = br.readLine();
			message1 = temp.split(" ");
			str = message1[1];
			n = Integer.parseInt(message1[3]);	
			
			CSetAttribute s = new CSetAttribute();
			s.m_attrname = str;
			m_attrList.add(s);
			
			if(n == 0){
				
				s.m_type = 1;
			}else{
				
				s.m_type = 2;
				
				for(int j=0; j<n; j++){
					
					temp = br.readLine();
					message1 = temp.split(" ");
					str = message1[1];
					CElementOfSet e = new CElementOfSet();
					e.m_Aset = str;
					s.m_set.add(e);
				}
			}
		}
		 
		 
	}
}
