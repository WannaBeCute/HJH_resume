var char = 'A'
console.log(char)
console.log(typeof(char))

var str = 'hello world'
console.log(str)
console.log(typeof(str))

var str2 = new String('niewei')
console.log(str2)
console.log(typeof(str2))

var names = new Array('niewei',"zhangsan",'list')
console.log(names)
console.log(typeof(names))

var bool = true
console.log(bool)
console.log(typeof(bool))

function sayHello(a){
    console.log(a)
    alert('hello world')
}
sayHello('hello world')

var person = new Object();  //创建一个空对象 {}
console.log(person)
console.log(typeof(person))

person.name = 'hujiahua'    //添加一个属性，值为字符串
console.log(person)
console.log(person.name)

function eat(){
    console.log(person.name+ "正在吃东西")  // 拼接两个字符串
}

person.eat = eat
person.eat()


