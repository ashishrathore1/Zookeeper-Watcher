package com.snapdeal.servicediscovery;


public class Monitor {
	
	
	public static void main(String[] args) throws Exception {	
		ZookeeperWatcher zkWatcher = new ZookeeperWatcher("/smartstack/services", "10.41.80.111:2181");
		Thread watcher = new Thread(zkWatcher);
		watcher.start();
		Object ob = new Object();
		synchronized (ob) {
			ob.wait();
		}
		
	}
	

}
